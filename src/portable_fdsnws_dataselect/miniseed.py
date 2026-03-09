"""
Data extraction and transfer from miniSEED files.
"""

import math
import os
import bisect
from abc import ABC, abstractmethod
from dataclasses import dataclass
from logging import getLogger
from typing import Generator, NamedTuple, Optional

from pymseed import MS3Record, NSTMODULUS, sample_time, timestr2nstime

from portable_fdsnws_dataselect.msriterator import MSR_iterator

logger = getLogger(__name__)


class NoDataError(Exception):
    """Raised when no data matches the request."""


class RequestLimitExceededError(Exception):
    """Raised when the result would exceed the configured byte limit."""


class _TrimBound(NamedTuple):
    """One side of a byte-range trim window."""

    offset: int
    needs_trim: bool


class ExtractedDataSegment(ABC):
    """Abstract base for a chunk of extracted miniSEED data."""

    src_name: str

    @abstractmethod
    def write(self, wfile) -> None:
        """Write the data to *wfile*."""

    @property
    @abstractmethod
    def num_bytes(self) -> int:
        """Number of bytes in this segment."""


def trim_record(msr: MS3Record, earliest: int, latest: int) -> Optional[bytes]:
    """Trim a miniSEED record to the specified time window.

    If the record samples could not be decompressed or could not be
    trimmed, the original record is returned.

    :param msr: Parsed MS3Record (data need not be unpacked yet).
    :param earliest: Earliest time to retain, nanoseconds since Unix epoch.
    :param latest: Latest time to retain, nanoseconds since Unix epoch.
    :returns: Trimmed record bytes, original record on failure, or
              ``None`` if the record has no time coverage.
    """
    if msr.samplecnt == 0 and msr.samprate == 0.0:
        return None

    try:
        msr.unpack_data()
    except Exception:
        return msr.record

    starttime = msr.starttime
    endtime = msr.endtime
    sample_period_ns = msr.samprate_period_ns

    startidx = None
    endidx = None

    # Trim early samples to the earliest time
    if earliest and starttime < earliest <= endtime:
        startidx = math.ceil((earliest - starttime) / sample_period_ns)
        # Correct for truncated period_ns on non-round sample rates:
        # the true time of the previous sample may still be >= earliest.
        if startidx > 0 and sample_time(starttime, startidx - 1, msr.samprate) >= earliest:
            startidx -= 1
        msr.starttime = sample_time(starttime, startidx, msr.samprate)

    # Trim late samples to the latest time
    if latest and starttime <= latest < endtime:
        count = math.ceil((endtime - latest) / sample_period_ns)
        # Correct: the first "removed" sample may actually be <= latest.
        if count > 0 and sample_time(starttime, msr.samplecnt - count, msr.samprate) <= latest:
            count -= 1
        if count > 0:
            endidx = -count

    # Retain record sequence number for version 2 miniSEED
    if msr.formatversion == 2:
        sequence_number = msr.record[:6]
        msr.set_extra_header("/FDSN/Sequence", int(sequence_number.decode()))

    repacked = bytearray()
    for record in msr.generate(
        data_samples=msr.datasamples[startidx:endidx],
        sample_type=msr.sampletype,
    ):
        repacked.extend(record)

    return bytes(repacked) if repacked else msr.record


class MSRIDataSegment(ExtractedDataSegment):
    """Segment of data backed by an active MSR_iterator record."""

    def __init__(
        self,
        msri: MSR_iterator,
        sample_rate: float,
        start_time: int,
        end_time: int,
        src_name: str,
    ) -> None:
        """
        :param msri: Active MSR_iterator positioned at the desired record.
        :param sample_rate: Nominal sample rate of the data.
        :param start_time: Request start time as nanoseconds since Unix epoch.
        :param end_time: Request end time as nanoseconds since Unix epoch.
        :param src_name: Source name string used in log messages.
        """
        self.msri = msri
        self.sample_rate = sample_rate
        self.start_time = start_time
        self.end_time = end_time
        self.src_name = src_name

    def write(self, wfile) -> None:
        msr_start_ns = self.msri.get_starttime()
        msr_end_ns = self.msri.get_endtime()

        if msr_start_ns > self.end_time or msr_end_ns < self.start_time:
            return

        if self.sample_rate > 0 and (msr_start_ns < self.start_time or msr_end_ns > self.end_time):
            logger.debug(f"Trimming record {self.src_name} @ {msr_start_ns}")
            trimmed = trim_record(self.msri.msr, self.start_time, self.end_time)
            if trimmed:
                wfile.write(trimmed)
        else:
            logger.debug(f"Writing full record {self.src_name} @ {msr_start_ns}")
            wfile.write(bytes(self.msri.msr.record_mv))

    @property
    def num_bytes(self) -> int:
        return self.msri.msr.reclen


class FileDataSegment(ExtractedDataSegment):
    """Segment of data read directly from a byte range in a file."""

    def __init__(
        self,
        filename: str,
        start_byte: int,
        num_bytes: int,
        src_name: str,
    ) -> None:
        self.filename = filename
        self.start_byte = start_byte
        self._num_bytes = num_bytes
        self.src_name = src_name

    def write(self, wfile) -> None:
        with open(self.filename, "rb") as f:
            f.seek(self.start_byte)
            wfile.write(f.read(self._num_bytes))

    @property
    def num_bytes(self) -> int:
        return self._num_bytes


@dataclass(frozen=True, slots=True)
class _RequestRow:
    """Internal row used during data extraction pre-scan."""

    srcname: str
    filename: str
    starttime: int
    endtime: int
    start: _TrimBound
    end: _TrimBound
    bytes: int
    samplerate: float


class MiniseedDataExtractor:
    """Extract, trim, and validate miniSEED data segments."""

    def __init__(
        self,
        dp_replace: Optional[tuple[str, str]] = None,
        request_limit: int = 0,
    ) -> None:
        """
        :param dp_replace: Optional ``(regex, replacement)`` for rewriting data file paths.
        :param request_limit: Maximum number of bytes allowed per request (0 = unlimited).
        """
        import re

        if dp_replace:
            self._dp_replace_re = re.compile(dp_replace[0])
            self._dp_replace_sub = dp_replace[1]
        else:
            self._dp_replace_re = None
            self._dp_replace_sub = None
        self.request_limit = request_limit

    def handle_trimming(
        self, stime: int, etime: int, NRow
    ) -> tuple[_TrimBound, _TrimBound]:
        """
        Return byte-offset trim bounds for the data in ``[stime, etime]``.

        Uses the ``timeindex`` field of *NRow* to find the tightest byte range
        that covers the requested window.

        :param stime: Request start time as nanoseconds since Unix epoch.
        :param etime: Request end time as nanoseconds since Unix epoch.
        :returns: ``(_TrimBound(offset, needs_trim), _TrimBound(offset, needs_trim))``
        """
        row_stime = timestr2nstime(NRow.starttime)
        row_etime = timestr2nstime(NRow.endtime)

        block_start = int(NRow.byteoffset)
        block_end = block_start + int(NRow.bytes)

        if stime > row_stime or etime < row_etime:
            entries = [x.split("=>") for x in NRow.timeindex.split(",")]

            # Parse timeindex into parallel ns-time and byte-offset lists.
            # The timeindex stores epoch-second strings; convert to nanoseconds.
            times_ns: list[int] = []
            offsets: list[int] = []
            for entry in entries:
                if entry[0] == "latest":
                    times_ns.append(row_etime)
                else:
                    times_ns.append(int(float(entry[0]) * NSTMODULUS))
                offsets.append(int(entry[1]))

            s_index = bisect.bisect_left(times_ns, stime) - 1
            if s_index < 0:
                s_index = 0
            e_index = bisect.bisect_right(times_ns, etime)
            if e_index >= len(times_ns):
                e_index = -1

            return (
                _TrimBound(offsets[s_index], stime > row_stime),
                _TrimBound(offsets[e_index], etime < row_etime),
            )
        else:
            return (
                _TrimBound(block_start, False),
                _TrimBound(block_end, False),
            )

    def extract_data(
        self, index_rows
    ) -> Generator[ExtractedDataSegment, None, None]:
        """
        Yield :class:`ExtractedDataSegment` objects for all matching data.

        :param index_rows: Rows produced by ``fetch_index_rows``.
        :raises NoDataError: When no bytes match the request.
        :raises RequestLimitExceededError: When the result would exceed the limit.
        """
        # Pre-scan: build the work list and check the size limit.
        # The byte estimate is >= actual output (compressed data may expand on trim).
        total_bytes = 0
        request_rows: list[_RequestRow] = []

        try:
            for NRow in index_rows:
                srcname = "_".join(NRow[:4])
                filename = NRow.filename

                starttime = timestr2nstime(NRow.requeststart)
                endtime = timestr2nstime(NRow.requestend)

                start, end = self.handle_trimming(starttime, endtime, NRow)
                total_bytes += end.offset - start.offset
                if self.request_limit > 0 and total_bytes > self.request_limit:
                    raise RequestLimitExceededError(
                        f"Result exceeds limit of {self.request_limit} bytes"
                    )
                if self._dp_replace_re:
                    filename = self._dp_replace_re.sub(self._dp_replace_sub, filename)
                if not os.path.exists(filename):
                    raise RuntimeError(f"Data file does not exist: {filename}")

                request_rows.append(
                    _RequestRow(
                        srcname=srcname,
                        filename=filename,
                        starttime=starttime,
                        endtime=endtime,
                        start=start,
                        end=end,
                        bytes=NRow.bytes,
                        samplerate=NRow.samplerate,
                    )
                )
        except (RequestLimitExceededError, RuntimeError):
            raise
        except Exception as err:
            logger.exception("Error scanning data index")
            raise RuntimeError(f"Error accessing data index: {err}") from err

        if total_bytes == 0:
            raise NoDataError

        for NRow in request_rows:
            logger.debug(
                f"Extracting {NRow.srcname} ({NRow.starttime} - {NRow.endtime}) "
                f"from {NRow.filename}"
            )

            if NRow.start.needs_trim or NRow.end.needs_trim:
                # Iterate record-by-record through the trimmed section
                for msri in MSR_iterator(
                    filename=NRow.filename,
                    startoffset=NRow.start.offset,
                    dataflag=False,
                ):
                    offset = msri.get_offset()

                    if offset >= NRow.end.offset:
                        break

                    yield MSRIDataSegment(
                        msri, NRow.samplerate, NRow.starttime, NRow.endtime, NRow.srcname
                    )

                    if (offset + msri.msr.reclen) >= NRow.end.offset:
                        break
            else:
                yield FileDataSegment(
                    NRow.filename, NRow.start.offset, NRow.bytes, NRow.srcname
                )
