"""
FDSN dataselect request parsing and validation.
"""

import datetime
import itertools
import re
from logging import getLogger
from urllib.parse import parse_qs, urlparse

from portable_fdsnws_dataselect import version

logger = getLogger(__name__)

#: Parameters that apply to the entire query (key=value pairs in a POST body)
BULK_PARAM_KEYS = ("quality", "minimumlength", "longestonly", "format", "nodata")

#: Short-form parameter aliases
PARAM_SUBSTITUTIONS: dict[str, str] = {
    "start": "starttime",
    "end": "endtime",
    "loc": "location",
    "net": "network",
    "sta": "station",
    "cha": "channel",
}

#: Default parameter values
DEFAULT_PARAMS: dict[str, str] = {
    "starttime": "1900-01-01T00:00:00.000000",
    "endtime": "2100-01-01T00:00:00.000000",
    "format": "miniseed",
    "nodata": "204",
    "network": "*",
    "station": "*",
    "location": "*",
    "channel": "*",
    "quality": "B",
    "minimumlength": "0.0",
    "longestonly": "FALSE",
}

#: Parameters required for any data query
REQUIRED_PARAMS = ("starttime", "endtime")

#: Valid endpoint names
QUERY_ENDPOINTS = ("query", "queryauth", "summary", "version", "application.wadl")

# Pre-compiled patterns for selection line validation
_ID_RE = re.compile(r"^[-0-9a-zA-Z,?*]+$")
_TIME_RE = re.compile(r"^[-:T.*\d]+$")


def parse_datetime(timestring: str) -> datetime.datetime:
    """
    Parse *timestring* using the supported FDSN date-time formats.

    :raises QueryError: When none of the supported formats match.
    """
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(timestring, fmt)
        except ValueError:
            pass
    raise QueryError(
        f"Datetime '{timestring}' not formatted as one of "
        "YYYY-MM-DDTHH:MM:SS.ssssss, YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD"
    )


def normalize_datetime(timestring: str) -> str:
    """Normalize *timestring* to ``YYYY-MM-DDThh:mm:ss.ffffff`` format."""
    return parse_datetime(timestring).strftime("%Y-%m-%dT%H:%M:%S.%f")


class QueryError(Exception):
    """Raised for invalid or unsupported request parameters."""


class NonQueryURLError(Exception):
    """Raised when the URL path does not correspond to a data query endpoint."""


class DataselectRequest:
    """Parse, validate, and expose a dataselect request."""

    #: Endpoint name (e.g. ``"query"``)
    endpoint: str
    #: Service-relative path (e.g. ``"/fdsnws/dataselect/1/query"``)
    path: str
    #: Time/channel selection rows ``[[net, sta, loc, cha, start, end], ...]``
    query_rows: list[list[str]]
    #: Non-row parameters such as ``format``, ``nodata``, ``quality``
    bulk_params: dict[str, str]

    def __init__(self, path: str, body: str | None = None) -> None:
        """
        Parse *path* (with optional query string) and optional POST *body*.

        :raises QueryError: For invalid parameters.
        :raises NonQueryURLError: When *path* is not a recognised endpoint.
        """
        req = urlparse(path)
        self.path = req.path.lower()
        self.endpoint = self.get_path_endpoint(self.path)
        logger.debug(f"Request endpoint: {self.endpoint}")
        if self.endpoint in ("query", "queryauth", "summary"):
            if not body:
                body = self.parse_query(req.query)
                logger.debug(f"GET request translated to request body:\n{body}")
            self.parse_request(body)

    def get_path_endpoint(self, path: str) -> str:
        """
        Return the endpoint name for *path* or raise :exc:`NonQueryURLError`.

        >>> DataselectRequest.get_path_endpoint(None, '/fdsnws/dataselect/1/query')
        'query'
        """
        prefix = f"/fdsnws/dataselect/{version[0]}/"
        if not path.startswith(prefix):
            raise NonQueryURLError(path)
        tail = path[len(prefix):]
        if tail not in QUERY_ENDPOINTS:
            raise NonQueryURLError(path)
        return tail

    def parse_query(self, query: str) -> str:
        """
        Convert a GET query string into a POST-style text body.

        :raises QueryError: For unrecognised or duplicated parameters.
        """
        qry = parse_qs(query)
        sql_qry = dict(DEFAULT_PARAMS)
        required = list(REQUIRED_PARAMS)
        for k, v in qry.items():
            k = PARAM_SUBSTITUTIONS.get(k, k)
            if k not in sql_qry:
                raise QueryError(f"Unrecognized query parameter: '{k}'")
            if len(v) > 1:
                raise QueryError(f"Multiple '{k}' parameters not allowed.")
            if k in required:
                required.remove(k)
            sql_qry[k] = v[0]

        if required and self.endpoint != "summary":
            plural = "" if len(required) == 1 else "s"
            raise QueryError(f"Missing parameter{plural}: {', '.join(required)}")

        bulk = [f"{k}={sql_qry[k]}" for k in BULK_PARAM_KEYS]
        bulk.append(
            " ".join(
                (
                    sql_qry["network"],
                    sql_qry["station"],
                    sql_qry["location"],
                    sql_qry["channel"],
                    sql_qry["starttime"],
                    sql_qry["endtime"],
                )
            )
        )
        return "\n".join(bulk)

    def parse_request(self, request_text: str) -> None:
        """
        Parse a POST-style request body into :attr:`bulk_params` and :attr:`query_rows`.

        The body format is::

            quality=B
            NET STA LOC CHA StartTime EndTime
            ...

        :raises QueryError: For malformed or unsupported content.
        """
        self.query_rows = []
        self.bulk_params = {k: DEFAULT_PARAMS[k] for k in BULK_PARAM_KEYS}
        inprefix = True

        for line in request_text.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if inprefix:
                keyval = line.split("=")
                if len(keyval) == 2 and keyval[0].lower() in self.bulk_params:
                    self.bulk_params[keyval[0].lower()] = keyval[1]
                    continue
                inprefix = False

            fields = line.split()
            if len(fields) != 6:
                raise QueryError(f"Unrecognized selection line: '{line}'")

            for idf in fields[:4]:
                if not _ID_RE.match(idf):
                    raise QueryError(f"Unrecognized selection identifier: '{line}'")

            for tidx in (4, 5):
                if not _TIME_RE.match(fields[tidx]):
                    raise QueryError(f"Unrecognized selection time: '{line}'")
                if fields[tidx] != "*":
                    try:
                        fields[tidx] = normalize_datetime(fields[tidx])
                    except Exception:
                        raise QueryError(f"Cannot normalize time: {fields[tidx]}")

            for net, sta, loc, cha in itertools.product(
                fields[0].split(","),
                fields[1].split(","),
                fields[2].split(","),
                fields[3].split(","),
            ):
                self.query_rows.append([net, sta, loc, cha, fields[4], fields[5]])

        if self.bulk_params["format"] not in ("miniseed",):
            raise QueryError(f"Unsupported format: '{self.bulk_params['format']}'")

        if self.bulk_params["nodata"] not in ("204", "404"):
            raise QueryError("nodata must be one of 204 or 404")

        if self.bulk_params["quality"] not in ("D", "R", "Q", "M", "B"):
            raise QueryError("quality must be one of B, D, R, M or Q")

        if self.bulk_params["minimumlength"] != DEFAULT_PARAMS["minimumlength"]:
            raise QueryError("minimumlength is not supported")

        if self.bulk_params["longestonly"] != DEFAULT_PARAMS["longestonly"]:
            raise QueryError("longestonly is not supported")

        if not self.query_rows:
            raise QueryError("No data selection present")
