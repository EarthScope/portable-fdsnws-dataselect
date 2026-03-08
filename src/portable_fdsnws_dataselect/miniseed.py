# -*- coding: utf-8 -*-
"""
Data extraction and transfer from miniSEED files
"""

import re
import os
import bisect

from logging import getLogger
from collections import namedtuple
from pymseed import MS3Record, NSTMODULUS, sample_time, timestr2nstime
from portable_fdsnws_dataselect.msriterator import MSR_iterator

logger = getLogger(__name__)


class NoDataError(Exception):
    """
    Error raised when no data is found
    """
    pass


class RequestLimitExceededError(Exception):
    """
    Error raised when the amount of data exceeds the configured limit
    """
    pass


class ExtractedDataSegment(object):
    """
    There are a few different forms that a chunk of extracted data can take, so we return
    a wrapped object that exposes a simple, consistent API for the handler to use.
    """
    def write(self, wfile):
        """
        Write the data to the given file-like object
        """
        raise NotImplementedError()

    def get_num_bytes(self):
        """
        Return the number of bytes in the segment
        """
        raise NotImplementedError()

    def get_src_name(self):
        """
        Return the name of the data source
        """
        raise NotImplementedError()


class MSRIDataSegment(ExtractedDataSegment):
    """
    Segment of data from a MSR_iterator
    """
    def __init__(self, msri, sample_rate, start_time, end_time, src_name):
        """
        :param msri: A `MSR_iterator`
        :param sample_rate: Sample rate of the data
        :param start_time: Start of the requested data as nanoseconds since Unix epoch
        :param end_time: End of the requested data as nanoseconds since Unix epoch
        :param src_name: Name of the data source for logging
        """
        self.msri = msri
        self.sample_rate = sample_rate
        self.start_time = start_time
        self.end_time = end_time
        self.src_name = src_name

    def write(self, wfile):
        msrstart = self.msri.get_startepoch()
        msrend = self.msri.get_endepoch()

        sepoch = self.start_time / NSTMODULUS
        eepoch = self.end_time / NSTMODULUS

        # Process records that intersect with request time window
        if msrstart <= eepoch and msrend >= sepoch:

            # Trim record if coverage and partial overlap with request
            if self.sample_rate > 0 and (msrstart < sepoch or msrend > eepoch):
                logger.debug("Trimming record %s @ %s" % (self.src_name, self.msri.get_starttime()))

                record_bytes = self.msri.msr.record
                for rec in MS3Record.from_buffer(record_bytes, unpack_data=True):
                    period_ns = rec.samprate_period_ns
                    rec_start_ns = rec.starttime
                    rec_end_ns = rec.endtime

                    # First sample at or after requested start (ceiling division)
                    if self.start_time > rec_start_ns:
                        start_idx = -(-(self.start_time - rec_start_ns) // period_ns)
                    else:
                        start_idx = 0

                    # Last sample at or before requested end (floor division)
                    if self.end_time < rec_end_ns:
                        end_idx = (self.end_time - rec_start_ns) // period_ns
                    else:
                        end_idx = rec.numsamples - 1

                    if start_idx > end_idx or start_idx >= rec.numsamples:
                        return

                    trimmed_samples = list(rec.datasamples[start_idx:end_idx + 1])
                    new_starttime = sample_time(rec_start_ns, start_idx, rec.samprate)

                    out_rec = MS3Record()
                    out_rec.sourceid = rec.sourceid
                    out_rec.starttime = new_starttime
                    out_rec.samprate = rec.samprate_raw
                    out_rec.encoding = rec.encoding
                    out_rec.pubversion = rec.pubversion
                    out_rec.formatversion = rec.formatversion
                    out_rec.reclen = rec.reclen

                    for packed_record in out_rec.generate(
                            data_samples=trimmed_samples, sample_type=rec.sampletype):
                        wfile.write(packed_record)

            # Otherwise, write un-trimmed record
            else:
                logger.debug("Writing full record %s @ %s" % (self.src_name, self.msri.get_starttime()))
                wfile.write(bytes(self.msri.msr.record_mv))

    def get_num_bytes(self):
        return self.msri.msr.reclen

    def get_src_name(self):
        return self.src_name


class FileDataSegment(ExtractedDataSegment):
    """
    Segment of data that comes directly from a data file
    """
    def __init__(self, filename, start_byte, num_bytes, src_name):
        """
        :param filename: Name of data file
        :param start_byte: Return data starting from this offset
        :param num_bytes: Length of data to return
        :param src_name: Name of the data source for logging
        """
        self.filename = filename
        self.start_byte = start_byte
        self.num_bytes = num_bytes
        self.src_name = src_name

    def write(self, wfile):
        with open(self.filename, "rb") as f:
            f.seek(self.start_byte)
            raw_data = f.read(self.num_bytes)
            wfile.write(raw_data)

    def get_num_bytes(self):
        return self.num_bytes

    def get_src_name(self):
        return self.src_name


class MiniseedDataExtractor(object):
    """
    Component for extracting, trimming, and validating data.
    """
    def __init__(self, dp_replace=None, request_limit=0):
        """
        :param dp_replace: optional tuple of (regex, replacement) indicating the location of data files
        :param request_limit: optional limit (in bytes) on how much data can be extracted at once
        """
        if dp_replace:
            self.dp_replace_re = re.compile(dp_replace[0])
            self.dp_replace_sub = dp_replace[1]
        else:
            self.dp_replace_re = None
            self.dp_replace_sub = None
        self.request_limit = request_limit

    def handle_trimming(self, stime, etime, NRow):
        """
        Get the time & byte-offsets for the data in time range (stime, etime).

        This is done by finding the smallest section of the data in row that
        falls within the desired time range and is identified by the timeindex
        field of row.

        :param stime: Start time as nanoseconds since Unix epoch
        :param etime: End time as nanoseconds since Unix epoch
        :returns: [(start time epoch, start offset, trim_boolean),
                   (end time epoch, end offset, trim_boolean)]
        """

        row_stime = timestr2nstime(NRow.starttime)
        row_etime = timestr2nstime(NRow.endtime)

        # If we need a subset of the this block, trim it accordingly
        block_start = int(NRow.byteoffset)
        block_end = block_start + int(NRow.bytes)
        if stime > row_stime or etime < row_etime:
            tix = [x.split("=>") for x in NRow.timeindex.split(",")]
            if tix[-1][0] == 'latest':
                tix[-1] = [str(row_etime / NSTMODULUS), block_end]
            to_x = [float(x[0]) for x in tix]
            s_index = bisect.bisect_left(to_x, stime / NSTMODULUS) - 1
            if s_index < 0:
                s_index = 0
            e_index = bisect.bisect_right(to_x, etime / NSTMODULUS)
            off_start = int(tix[s_index][1])
            if e_index >= len(tix):
                e_index = -1
            off_end = int(tix[e_index][1])
            return ([to_x[s_index], off_start, stime > row_stime],
                    [to_x[e_index], off_end, etime < row_etime],)
        else:
            return ([row_stime / NSTMODULUS, block_start, False],
                    [row_etime / NSTMODULUS, block_end, False])

    def extract_data(self, index_rows):
        """
        Perform the data extraction.

        :param index_rows: requested data, as produced by `HTTPServer_RequestHandler.fetch_index_rows`
        :yields: sequence of `ExtractedDataSegment`s
        """

        # Pre-scan the index rows:
        # 1) Build processed list for extraction
        # 2) Check if the request is small enough to satisfy
        # Note: accumulated estimate of output bytes will be equal to or higher than actual output
        total_bytes = 0
        request_rows = []
        Request = namedtuple('Request', ['srcname', 'filename', 'starttime', 'endtime',
                                         'triminfo', 'bytes', 'samplerate'])
        try:
            for NRow in index_rows:
                srcname = "_".join(NRow[:4])
                filename = NRow.filename

                logger.debug("EXTRACT: src=%s, file=%s, bytes=%s, rate:%s" %
                             (srcname, filename, NRow.bytes, NRow.samplerate))

                starttime = timestr2nstime(NRow.requeststart)
                endtime = timestr2nstime(NRow.requestend)

                triminfo = self.handle_trimming(starttime, endtime, NRow)
                total_bytes += triminfo[1][1] - triminfo[0][1]
                if self.request_limit > 0 and total_bytes > self.request_limit:
                    raise RequestLimitExceededError("Result exceeds limit of %d bytes" % self.request_limit)
                if self.dp_replace_re:
                    filename = self.dp_replace_re.sub(self.dp_replace_sub, filename)
                if not os.path.exists(filename):
                    raise Exception("Data file does not exist: %s" % filename)
                request_rows.append(Request(srcname=srcname,
                                            filename=filename,
                                            starttime=starttime,
                                            endtime=endtime,
                                            triminfo=triminfo,
                                            bytes=NRow.bytes,
                                            samplerate=NRow.samplerate))
                logger.debug("EXTRACT: src=%s, file=%s, bytes=%s, rate:%s" %
                             (srcname, filename, NRow.bytes, NRow.samplerate))
        except Exception as err:
            import traceback
            traceback.print_exc()
            raise Exception("Error accessing data index: %s" % str(err))

        # Error if request matches no data
        if total_bytes == 0:
            raise NoDataError()

        # Get & return the actual data
        for NRow in request_rows:
            logger.debug("Extracting %s (%s - %s) from %s" % (NRow.srcname, NRow.starttime,
                                                              NRow.endtime, NRow.filename))

            # Iterate through records in section if only part of the section is needed
            if NRow.triminfo[0][2] or NRow.triminfo[1][2]:

                for msri in MSR_iterator(filename=NRow.filename,
                                         startoffset=NRow.triminfo[0][1],
                                         dataflag=False):
                    offset = msri.get_offset()

                    # Done if we are beyond end offset
                    if offset >= NRow.triminfo[1][1]:
                        break

                    yield MSRIDataSegment(msri, NRow.samplerate, NRow.starttime,
                                          NRow.endtime, NRow.srcname)

                    # Check for passing end offset
                    if (offset + msri.msr.reclen) >= NRow.triminfo[1][1]:
                        break

            # Otherwise, return the entire section
            else:
                yield FileDataSegment(NRow.filename, NRow.triminfo[0][1],
                                      NRow.bytes, NRow.srcname)
