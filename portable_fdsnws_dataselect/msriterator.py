# -*- coding: utf-8 -*-
"""
Convenience class for iterating over miniSEED records in a file.
"""

import os

from pymseed import MS3Record
from pymseed.msrecord_reader import MS3RecordReader


class MSR_iterator(object):
    """
    Class for iterating through miniSEED records in a file.

    :ivar msr: Current MS3Record
    :ivar file: filename

    :param filename: File to read
    :param startoffset: Offset in bytes to start reading the file
    :param dataflag: Controls whether data samples are unpacked, defaults
        to False.
    :param skipnotdata: If true any data chunks that do not have valid data
        record indicators will be skipped. Defaults to True (1).
    :param verbose: Controls verbosity from 0 to 2. Defaults to 0.

    .. rubric:: Example

    from msriterator import MSR_iterator

    mseedfile = "test.mseed"

    for msri in MSR_iterator(filename=mseedfile, dataflag=False):

        print ("{:d}: {}, reclen: {}, samples: {}, starttime: {}, endtime: {}".
               format(msri.get_offset(),
                      msri.get_srcname(),
                      msri.msr.reclen,
                      msri.msr.samplecnt,
                      msri.get_starttime(),
                      msri.get_endtime()))
    """

    def __init__(self, filename, startoffset=0,
                 reclen=-1, dataflag=0, skipnotdata=1, verbose=0,
                 raise_errors=True):

        self.file = filename
        self._offset = startoffset
        self._next_offset = startoffset
        self.msr = None

        flags = os.O_RDONLY
        if hasattr(os, 'O_BINARY'):
            flags |= os.O_BINARY
        self._fd = os.open(filename, flags)
        if startoffset != 0:
            os.lseek(self._fd, startoffset, os.SEEK_SET)

        self._reader = MS3RecordReader(
            self._fd,
            unpack_data=bool(dataflag),
            skip_not_data=bool(skipnotdata),
            verbose=verbose,
        )

    def __iter__(self):
        return self

    def __next__(self):
        """
        Read next record from file.
        """
        self._offset = self._next_offset
        record = self._reader.read()
        if record is None:
            raise StopIteration()
        self.msr = record
        self._next_offset = self._offset + record.reclen
        return self

    def __del__(self):
        """
        Close reader and file descriptor.
        """
        try:
            if hasattr(self, '_reader') and self._reader is not None:
                self._reader.close()
                self._reader = None
        except Exception:
            pass
        try:
            if hasattr(self, '_fd') and self._fd >= 0:
                os.close(self._fd)
                self._fd = -1
        except Exception:
            pass

    def get_srcname(self, quality=False):
        """
        Return record source identifier
        """
        return self.msr.sourceid or ""

    def get_starttime(self):
        """
        Return record start time as nanoseconds since Unix epoch
        """
        return self.msr.starttime

    def get_endtime(self):
        """
        Return record end time as nanoseconds since Unix epoch
        """
        return self.msr.endtime

    def get_startepoch(self):
        """
        Return record start time as epoch seconds (float)
        """
        return self.msr.starttime_seconds

    def get_endepoch(self):
        """
        Return record end time as epoch seconds (float)
        """
        return self.msr.endtime_seconds

    def set_offset(self, value):
        """
        Set file reading position
        """
        self._offset = value
        self._next_offset = value

    def get_offset(self):
        """
        Return offset into file for current record
        """
        return self._offset

    offset = property(get_offset, set_offset)
