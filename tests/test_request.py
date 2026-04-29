"""
Tests for DataselectRequest parsing and validation.
"""

from __future__ import annotations

import pytest

from portable_fdsnws_dataselect.request import (
    DataselectRequest,
    NonQueryURLError,
    QueryError,
    parse_datetime,
)

# FDSN dataselect service URL path version (per FDSN spec, not the package version)
V = 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _post(body: str) -> DataselectRequest:
    """POST to the query endpoint with the given body."""
    return DataselectRequest(f"/fdsnws/dataselect/{V}/query", body)


# ---------------------------------------------------------------------------
# GET – basic and aliases
# ---------------------------------------------------------------------------

def test_get_basic():
    request = DataselectRequest(
        f"/fdsnws/dataselect/{V}/query?net=IU&start=2017-01-01&end=2017-01-02"
    )
    assert request.endpoint == "query"
    assert request.query_rows == [
        ["IU", "*", "*", "*", "2017-01-01T00:00:00.000000", "2017-01-02T00:00:00.000000"]
    ]


def test_get_multiples():
    request = DataselectRequest(
        f"/fdsnws/dataselect/{V}/query?net=IU,II&sta=ANMO,CULA&start=2017-01-01&end=2017-01-02"
    )
    assert request.endpoint == "query"
    assert len(request.query_rows) == 4


def test_get_aliases():
    """Short-form aliases (net/sta/loc/cha/start/end) must map to full names."""
    short = DataselectRequest(
        f"/fdsnws/dataselect/{V}/query"
        "?net=IU&sta=ANMO&loc=00&cha=LHZ&start=2017-01-01&end=2017-01-02"
    )
    full = DataselectRequest(
        f"/fdsnws/dataselect/{V}/query"
        "?network=IU&station=ANMO&location=00&channel=LHZ"
        "&starttime=2017-01-01&endtime=2017-01-02"
    )
    assert short.query_rows == full.query_rows


def test_get_duplicate_param():
    """A query parameter supplied twice must raise QueryError."""
    with pytest.raises(QueryError):
        DataselectRequest(
            f"/fdsnws/dataselect/{V}/query?net=IU&net=II&start=2017-01-01&end=2017-01-02"
        )


def test_get_missing_param():
    with pytest.raises(QueryError):
        DataselectRequest(f"/fdsnws/dataselect/{V}/query?net=IU")


def test_get_unknown_param():
    with pytest.raises(QueryError):
        DataselectRequest(
            f"/fdsnws/dataselect/{V}/query?net=IU&start=2017-01-01&end=2017-01-02&foo=bar"
        )


def test_get_bad_date():
    with pytest.raises(QueryError):
        DataselectRequest(
            f"/fdsnws/dataselect/{V}/query?net=IU&start=201-01-01&end=2017-01-02"
        )


# ---------------------------------------------------------------------------
# GET – endpoint dispatch
# ---------------------------------------------------------------------------

def test_endpoint_version():
    r = DataselectRequest(f"/fdsnws/dataselect/{V}/version")
    assert r.endpoint == "version"


def test_endpoint_wadl():
    r = DataselectRequest(f"/fdsnws/dataselect/{V}/application.wadl")
    assert r.endpoint == "application.wadl"


def test_endpoint_summary_no_times():
    """summary endpoint must not require starttime/endtime."""
    r = DataselectRequest(f"/fdsnws/dataselect/{V}/summary?net=IU")
    assert r.endpoint == "summary"
    assert len(r.query_rows) == 1


def test_endpoint_queryauth_with_times():
    r = DataselectRequest(
        f"/fdsnws/dataselect/{V}/queryauth?net=IU&start=2017-01-01&end=2017-01-02"
    )
    assert r.endpoint == "queryauth"


def test_endpoint_unknown_tail():
    with pytest.raises(NonQueryURLError):
        DataselectRequest(f"/fdsnws/dataselect/{V}/invalid")


def test_endpoint_wrong_service_version():
    """A path using the package version (2) instead of the FDSN service version (1)
    must raise NonQueryURLError."""
    with pytest.raises(NonQueryURLError):
        DataselectRequest(
            "/fdsnws/dataselect/2/query?net=IU&start=2017-01-01&end=2017-01-02"
        )


def test_endpoint_wrong_prefix():
    with pytest.raises(NonQueryURLError):
        DataselectRequest("/fdsnws/notaservice/1/query")


# ---------------------------------------------------------------------------
# POST – happy paths
# ---------------------------------------------------------------------------

def test_post_basic():
    r = _post("IU ANMO 00 LHZ 2017-01-01T00:00:00 2017-01-02T00:00:00\n")
    assert r.endpoint == "query"
    assert r.query_rows == [
        ["IU", "ANMO", "00", "LHZ", "2017-01-01T00:00:00.000000", "2017-01-02T00:00:00.000000"]
    ]


def test_post_quality_bulk_param():
    r = _post("quality=D\nIU ANMO 00 LHZ 2017-01-01T00:00:00 2017-01-02T00:00:00\n")
    assert r.bulk_params["quality"] == "D"
    assert len(r.query_rows) == 1


def test_post_nodata_bulk_param():
    r = _post("nodata=404\nIU ANMO 00 LHZ 2017-01-01T00:00:00 2017-01-02T00:00:00\n")
    assert r.bulk_params["nodata"] == "404"


def test_post_multiple_rows():
    body = (
        "IU ANMO 00 LHZ 2017-01-01 2017-01-02\n"
        "II BFO 00 BHZ 2017-01-01 2017-01-02\n"
    )
    r = _post(body)
    assert len(r.query_rows) == 2
    assert r.query_rows[0][0] == "IU"
    assert r.query_rows[1][0] == "II"


def test_post_comments_and_blank_lines_ignored():
    body = (
        "# This is a comment\n"
        "\n"
        "quality=M\n"
        "# Another comment\n"
        "\n"
        "IU ANMO 00 LHZ 2017-01-01 2017-01-02\n"
    )
    r = _post(body)
    assert r.bulk_params["quality"] == "M"
    assert len(r.query_rows) == 1


def test_post_comma_expansion():
    """Comma-separated identifiers in a POST row must expand via Cartesian product."""
    body = "IU,II ANMO,CULA 00 LHZ 2017-01-01 2017-01-02\n"
    r = _post(body)
    assert len(r.query_rows) == 4
    nets = {row[0] for row in r.query_rows}
    stas = {row[1] for row in r.query_rows}
    assert nets == {"IU", "II"}
    assert stas == {"ANMO", "CULA"}


def test_post_wildcard_times():
    """Wildcard * times must pass through validation unchanged."""
    body = "IU ANMO 00 LHZ * *\n"
    r = _post(body)
    assert r.query_rows[0][4] == "*"
    assert r.query_rows[0][5] == "*"


def test_post_date_formats():
    """All three supported date formats must normalize to microsecond precision."""
    for time_str, expected in [
        ("2017-01-01T12:30:45.123456", "2017-01-01T12:30:45.123456"),
        ("2017-01-01T12:30:45", "2017-01-01T12:30:45.000000"),
        ("2017-01-01", "2017-01-01T00:00:00.000000"),
    ]:
        r = _post(f"IU ANMO 00 LHZ {time_str} 2017-01-02\n")
        assert r.query_rows[0][4] == expected


# ---------------------------------------------------------------------------
# POST – validation errors
# ---------------------------------------------------------------------------

def test_post_wrong_field_count():
    with pytest.raises(QueryError, match="Unrecognized selection line"):
        _post("IU ANMO 00 LHZ 2017-01-01\n")


def test_post_bad_identifier():
    with pytest.raises(QueryError, match="Unrecognized selection identifier"):
        _post("IU ANMO@bad 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_bad_time():
    with pytest.raises(QueryError):
        _post("IU ANMO 00 LHZ 2017-13-01 2017-01-02\n")


def test_post_unsupported_format():
    with pytest.raises(QueryError, match="Unsupported format"):
        _post("format=seedlink\nIU ANMO 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_invalid_nodata():
    with pytest.raises(QueryError, match="nodata"):
        _post("nodata=200\nIU ANMO 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_invalid_quality():
    with pytest.raises(QueryError, match="quality"):
        _post("quality=Z\nIU ANMO 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_minimumlength_rejected():
    with pytest.raises(QueryError, match="minimumlength"):
        _post("minimumlength=1.0\nIU ANMO 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_longestonly_rejected():
    with pytest.raises(QueryError, match="longestonly"):
        _post("longestonly=TRUE\nIU ANMO 00 LHZ 2017-01-01 2017-01-02\n")


def test_post_no_selection_rows():
    with pytest.raises(QueryError, match="No data selection"):
        _post("quality=D\n")


# ---------------------------------------------------------------------------
# parse_datetime
# ---------------------------------------------------------------------------

def test_parse_datetime_full():
    dt = parse_datetime("2017-06-15T12:30:45.123456")
    assert dt.year == 2017
    assert dt.microsecond == 123456


def test_parse_datetime_no_microseconds():
    dt = parse_datetime("2017-06-15T12:30:45")
    assert dt.second == 45
    assert dt.microsecond == 0


def test_parse_datetime_date_only():
    dt = parse_datetime("2017-06-15")
    assert dt.year == 2017
    assert dt.month == 6
    assert dt.day == 15
    assert dt.hour == 0


def test_parse_datetime_invalid():
    with pytest.raises(QueryError):
        parse_datetime("2017-06-15T12:30")  # missing seconds


def test_parse_datetime_garbage():
    with pytest.raises(QueryError):
        parse_datetime("not-a-date")
