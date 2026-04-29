"""
Unit tests for MiniseedDataExtractor.handle_trimming.

Values are taken from the LHZ row in tests/testdata/timeseries.sqlite (mseed2 file):
  byteoffset=36352, bytes=18432  → block_start=36352, block_end=54784
  starttime='2010-02-27T06:50:00.069539'  (ns: 1267253400069539000)
  endtime='2010-02-27T07:59:59.069538'    (ns: 1267257599069538000)
  timeindex='1267253400.069539=>36352,1267256952.069538=>51200,latest=>1'
    times_ns[0] = 1267253400069539000  offsets[0] = 36352
    times_ns[1] = 1267256952069538000  offsets[1] = 51200
    times_ns[2] = row_etime (from 'latest') = 1267257599069538000  offsets[2] = 1
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from pymseed import NSTMODULUS
from portable_fdsnws_dataselect.miniseed import MiniseedDataExtractor, _TrimBound

# ---------------------------------------------------------------------------
# Fixture row values (LHZ, mseed2 file)
# ---------------------------------------------------------------------------

BLOCK_START = 36352
BLOCK_END = 54784          # 36352 + 18432

ROW_STIME_STR = "2010-02-27T06:50:00.069539"
ROW_ETIME_STR = "2010-02-27T07:59:59.069538"

NS_T1 = 1267253400069539000   # row_stime, timeindex[0]
NS_T2 = 1267256952069538000   # timeindex[1]
NS_T3 = 1267257599069538000   # row_etime  (mapped from 'latest')

TIMEINDEX_2 = f"1267253400.069539=>{BLOCK_START},1267256952.069538=>51200"
TIMEINDEX_LATEST = f"1267253400.069539=>{BLOCK_START},1267256952.069538=>51200,latest=>1"


def _row(timeindex: str = TIMEINDEX_2) -> SimpleNamespace:
    """Return a stand-in for an IndexRow with LHZ values."""
    return SimpleNamespace(
        starttime=ROW_STIME_STR,
        endtime=ROW_ETIME_STR,
        byteoffset=BLOCK_START,
        bytes=18432,
        timeindex=timeindex,
    )


@pytest.fixture
def extractor() -> MiniseedDataExtractor:
    return MiniseedDataExtractor()


# ---------------------------------------------------------------------------
# Window fully covering the row → else branch, no trimming
# ---------------------------------------------------------------------------

def test_full_coverage_returns_block_bounds(extractor):
    """When the request spans the entire row, return block_start/block_end with
    needs_trim=False on both ends."""
    start, end = extractor.handle_trimming(NS_T1, NS_T3, _row())
    assert start == _TrimBound(BLOCK_START, False)
    assert end == _TrimBound(BLOCK_END, False)


# ---------------------------------------------------------------------------
# Regression: endtime past the last timeindex entry → must return block_end
# ---------------------------------------------------------------------------

def test_endtime_past_block_returns_block_end(extractor):
    """Regression for silent-hang bug: when etime exceeds the last indexed time
    the end offset must be block_end, not the start of the last record."""
    stime = NS_T2                           # > NS_T1 → forces the timeindex branch
    etime = NS_T3 + 3600 * NSTMODULUS      # well past row_etime

    start, end = extractor.handle_trimming(stime, etime, _row())

    assert end.offset == BLOCK_END, (
        f"Expected block_end={BLOCK_END}, got {end.offset}. "
        "The bug would return 51200 (start of last record)."
    )
    assert not end.needs_trim   # etime >= row_etime → no trim needed at the end


# ---------------------------------------------------------------------------
# starttime before first index entry → clamps to first offset
# ---------------------------------------------------------------------------

def test_starttime_before_first_entry_clamps(extractor):
    """stime before the row should clamp s_index to 0 (first offset)."""
    stime = NS_T1 - NSTMODULUS   # one second before row start
    etime = NS_T2 - NSTMODULUS   # before T2, well within the row

    start, end = extractor.handle_trimming(stime, etime, _row())

    assert start.offset == BLOCK_START   # clamped to offsets[0]
    assert not start.needs_trim          # stime <= row_stime, no start trim
    assert end.offset == 51200           # bisect gives offsets[1]
    assert end.needs_trim                # etime < row_etime


# ---------------------------------------------------------------------------
# Window inside indexed range → interior offsets, both ends trimmed
# ---------------------------------------------------------------------------

def test_window_inside_range_uses_interior_offsets(extractor):
    """A window that starts at row_stime but ends before T2 should use an
    interior end offset with needs_trim=True."""
    stime = NS_T1                              # == row_stime
    etime = NS_T1 + (NS_T2 - NS_T1) // 2     # halfway between T1 and T2

    start, end = extractor.handle_trimming(stime, etime, _row())

    # stime == row_stime → condition is True only via etime < row_etime
    assert start.offset == BLOCK_START
    assert not start.needs_trim   # stime is not > row_stime
    assert end.offset == 51200    # bisect_right([T1,T2], mid) = 1 → offsets[1]
    assert end.needs_trim         # etime < row_etime


# ---------------------------------------------------------------------------
# 'latest' sentinel maps to row_etime
# ---------------------------------------------------------------------------

def test_latest_sentinel_resolves_to_row_etime(extractor):
    """The 'latest' entry in timeindex must map to row_etime so that bisect
    finds it at the right position.  With etime == row_etime and stime == T2,
    e_index should be len(times_ns) (pointing past the 'latest' entry) and
    block_end should be returned."""
    stime = NS_T2   # > NS_T1 → forces timeindex branch
    etime = NS_T3   # == row_etime

    start, end = extractor.handle_trimming(stime, etime, _row(TIMEINDEX_LATEST))

    # bisect_right([T1, T2, T3], T3) == 3 == len → block_end
    assert end.offset == BLOCK_END
    assert not end.needs_trim   # etime == row_etime → not strictly less
