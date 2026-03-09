"""
Convenience class for iterating over miniSEED records in a file.
"""

import os
from types import TracebackType
from typing import Optional

from pymseed import MS3Record
from pymseed.msrecord_reader import MS3RecordReader


class MSR_iterator:
    """
    Iterate through miniSEED records in a file starting at an optional byte offset.

    Supports use as a context manager for deterministic resource cleanup:

        with MSR_iterator(filename="data.mseed") as msri:
            for rec in msri:
                print(rec.msr.reclen)

    Attributes:
        msr: The current MS3Record (valid only between iterations).
        file: Path to the source file.
    """

    def __init__(
        self,
        filename: str,
        startoffset: int = 0,
        dataflag: bool = False,
        skipnotdata: bool = True,
        verbose: int = 0,
    ) -> None:
        self.file = filename
        self._offset = startoffset
        self._next_offset = startoffset
        self.msr: Optional[MS3Record] = None

        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        self._fd = os.open(filename, flags)
        if startoffset != 0:
            os.lseek(self._fd, startoffset, os.SEEK_SET)

        self._reader = MS3RecordReader(
            self._fd,
            unpack_data=dataflag,
            skip_not_data=skipnotdata,
            verbose=verbose,
        )

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> "MSR_iterator":
        return self

    def __exit__(
        self,
        exc_type: Optional[type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the reader and the underlying file descriptor."""
        try:
            if getattr(self, "_reader", None) is not None:
                self._reader.close()
                self._reader = None
        except Exception:
            pass
        try:
            fd = getattr(self, "_fd", -1)
            if fd >= 0:
                os.close(fd)
                self._fd = -1
        except Exception:
            pass

    def __del__(self) -> None:
        self.close()

    # -- iterator protocol -----------------------------------------------------

    def __iter__(self) -> "MSR_iterator":
        return self

    def __next__(self) -> "MSR_iterator":
        """Read the next record from the file."""
        self._offset = self._next_offset
        record = self._reader.read()
        if record is None:
            raise StopIteration
        self.msr = record
        self._next_offset = self._offset + record.reclen
        return self

    # -- accessors -------------------------------------------------------------

    def get_starttime(self) -> int:
        """Return the record start time as nanoseconds since Unix epoch."""
        return self.msr.starttime

    def get_endtime(self) -> int:
        """Return the record end time as nanoseconds since Unix epoch."""
        return self.msr.endtime

    def get_offset(self) -> int:
        """Return the byte offset of the current record within the file."""
        return self._offset

    def set_offset(self, value: int) -> None:
        """Set the current byte offset (updates both current and next)."""
        self._offset = value
        self._next_offset = value

    offset = property(get_offset, set_offset)
