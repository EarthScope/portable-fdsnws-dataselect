"""
Tests for DataselectRequest parsing and validation.
"""

import pytest
from portable_fdsnws_dataselect.request import DataselectRequest, QueryError


# FDSN dataselect service URL path version (per FDSN spec, not the package version)
V = 1


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
