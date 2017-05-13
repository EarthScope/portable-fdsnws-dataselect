# -*- coding: utf-8 -*-
"""
HTTP request handler
"""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from future.builtins import *  # NOQA
from future.backports.urllib.parse import parse_qs, urlparse
from logging import getLogger
import os.path
import datetime
import re
from portable_fdsnws_dataselect import version, pkg_path

logger = getLogger(__name__)

#: Parameters that correspond to time/channel constraints (appear in rows in a POST request)
ROW_PARAM_KEYS = ('starttime', 'endtime', 'network', 'station', 'location', 'channel',)

#: Parameters that apply to the entire query (appear as key/value pairs in a POST request)
BULK_PARAM_KEYS = ('quality', 'minimumlength', 'longestonly', 'format', 'nodata',)

#: Alternate parameter names
PARAM_SUBSTITUTIONS = {
    'start': 'starttime',
    'end': 'endtime',
    'loc': 'location',
    'net': 'network',
    'sta': 'station',
    'cha': 'channel',
}

#: Default parameter values
DEFAULT_PARAMS = {
    'starttime': '1900-01-01T00:00:00.000000',
    'endtime': '2100-01-01T00:00:00.000000',
    'format': 'miniseed',
    'nodata': '204',
    'network': '*',
    'station': '*',
    'location': '*',
    'channel': '*',
    'quality': 'B',
    'minimumlength': '0.0',
    'longestonly': 'FALSE',
}

#: Parameters required for any query
REQUIRED_PARAMS = ('starttime', 'endtime',)

#: Valid endpoints
QUERY_ENDPOINTS = ('query', 'queryauth', 'summary', 'version', 'application.wadl',)


def parse_datetime(timestring):
    '''
    Try to parse the given time string according to our supported date formats
    '''
    try:
        return datetime.datetime.strptime(timestring, "%Y-%m-%dT%H:%M:%S.%f")
    except Exception:
        pass
    try:
        return datetime.datetime.strptime(timestring, "%Y-%m-%dT%H:%M:%S")
    except Exception:
        pass
    try:
        return datetime.datetime.strptime(timestring, "%Y-%m-%d")
    except Exception:
        pass
    raise QueryError("Datetime '%s' not formatted as one of YYYY-MM-DDTHH:MM:SS.ssssss, YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD" % timestring)


def normalize_datetime(timestring):
    '''Normalize time string to strict YYYY-MM-DDThh:mm:ss.ffffff format
    '''
    return parse_datetime(timestring).strftime("%Y-%m-%dT%H:%M:%S.%f")


class QueryError(Exception):
    """
    Error indicating bad data from the user
    """
    pass


class NonQueryURLError(Exception):
    """
    Error indicating that the user requested something other than a regular query
    """
    pass


class DataselectRequest(object):
    """
    Parse, validate, and expose a dataselect request.
    """

    #: Endpoint (eg. "query")
    endpoint = None
    #: Path relative to the service prefix (eg. "/fdsnws/dataselect/1/query")
    path = None
    #: Time/channel constraints in the form of POST-style lines
    query_rows = None
    #: Non-row parameters (eg. format, minimumlength)
    bulk_params = None

    def __init__(self, path, body=None):
        """
        Parse the given path (which may include query parameters) and (optional) POST body
        into a request.
        """
        req = urlparse(path)
        self.path = req.path.lower()
        self.endpoint = self.get_path_endpoint(self.path)
        logger.debug("Request endpoint: %s" % self.endpoint)
        # Only parse the body or query arguments for endpoints that need them
        if self.endpoint in ('query', 'queryauth', 'summary', ):
            if not body:
                body = self.parse_query(req.query)
                logger.debug("GET request translated to request body:\n%s" % body)
            self.parse_request(body)

    def get_path_endpoint(self, path):
        """
        Verify that the given path points to a valid endpoint, and return the endpoint.

        >>> DataselectRequest.get_path_endpoint(None, '/fdsnws/dataselect/1/query')
        'query'

        """
        # Check that it begins with /fdsnws/dataselect/1/
        prefix = '/fdsnws/dataselect/%d/' % version[0]
        if not path.startswith(prefix):
            raise NonQueryURLError(path)
        # Check for valid suffix to path & respond if not a data request
        path_tail = path[len(prefix):]
        if path_tail not in QUERY_ENDPOINTS:
            raise NonQueryURLError(path)
        return path_tail

    def parse_query(self, query):
        """
        Parse a GET query string and convert it into a POST-style text block.
        """
        qry = parse_qs(query)
        sql_qry = dict(DEFAULT_PARAMS)
        required = list(REQUIRED_PARAMS)
        for k, v in qry.items():
            k = PARAM_SUBSTITUTIONS.get(k, k)
            if k not in sql_qry:
                raise QueryError("Unrecognized query parameter: '%s'" % k)
            elif len(v) > 1:
                raise QueryError("Multiple '%s' parameters not allowed." % k)
            else:
                if k in required:
                    required.remove(k)
                v = v[0]
                if k.endswith('time'):
                    try:
                        v = normalize_datetime(v)
                    except QueryError as e:
                        raise QueryError("Failed to parse '%s': %s" % (k, e))
                elif k == 'quality':
                    if v not in ('D', 'R', 'Q', 'M', 'B'):
                        raise QueryError("quality must be one of B, D, R, M or Q")
                elif k == 'format':
                    if v.lower() not in ('miniseed'):
                        raise QueryError("Unsupported format: '%s'" % v)
                sql_qry[k] = v

        if len(required) > 0 and self.endpoint != 'summary':
            raise QueryError("Missing parameter%s: %s" % ("" if len(required) == 1 else "s", ", ".join(required)))

        # Build a string for the matching request as a POST body
        bulk = []
        for k in BULK_PARAM_KEYS:
            bulk.append("%s=%s" % (k, sql_qry[k]))
        for n in sql_qry['network'].split(","):
            for s in sql_qry['station'].split(","):
                for l in sql_qry['location'].split(","):
                    if l == '':
                        l = "--"
                    for c in sql_qry['channel'].split(","):
                        bulk.append(" ".join((
                            n, s, l, c, sql_qry['starttime'], sql_qry['endtime'])))

        return "\n".join(bulk)

    def parse_request(self, request_text):
        '''
        Read a specified request file and return it as a list of tuples.

        Format of initial lines should be key/value pairs, like:
          quality=<quality>
          minimumlength=<float>
          longestonly=<TRUE|FALSE>
        These key-value pairs (with default values if appropriate) will go into `self.bulk_params`

        Expected format for the remaining lines is:
          Network Station Location Channel StartTime EndTime

        where the fields are space delimited
        and Network, Station, Location and Channel may contain '*' and '?' wildcards
        and StartTime and EndTime are in YYYY-MM-DDThh:mm:ss.ssssss format or are '*'

        Empty locations must be indictaed with --

        Each line will be split into a list and added to `self.query_rows`
        '''
        self.query_rows = []
        self.bulk_params = dict(((k, DEFAULT_PARAMS[k]) for k in BULK_PARAM_KEYS))
        linenumber = 1
        linematch = re.compile('^[\w\?\*]{1,2}\s+[\w\?\*]{1,5}\s+[-\w\?\*]{1,2}\s+[\w\?\*]{1,3}\s+[-:T.*\d]+\s+[-:T.*\d]+$')
        inprefix = True

        # Parse the lines
        for linenumber, line in enumerate(request_text.split('\n')):
            line = line.strip()

            # Skip blank or commented-out lines
            if not line or line.startswith("#"):
                continue

            # Might be a prefix line; if not, assume no others are
            if inprefix:
                prefix_bits = line.split("=")
                if len(prefix_bits) == 2:
                    kind = prefix_bits[0].lower()
                    if kind in self.bulk_params:
                        self.bulk_params[kind] = prefix_bits[1]
                        continue
                inprefix = False

            # Add line to request list if it matches validation regex
            if linematch.match(line):
                fields = line.split()

                # Normalize start and end times to "YYYY-MM-DDThh:mm:ss.ffffff" if not wildcards
                if fields[4] != '*':
                    try:
                        fields[4] = normalize_datetime(fields[4])
                    except Exception:
                        raise QueryError("Cannot normalize start time (line {0:d}): {1:s}".format(linenumber, fields[4]))

                if fields[5] != '*':
                    try:
                        fields[5] = normalize_datetime(fields[5])
                    except Exception:
                        raise QueryError("Cannot normalize start time (line {0:d}): {1:s}".format(linenumber, fields[4]))

                self.query_rows.append(fields)

            else:
                raise QueryError("Unrecognized selection line ({0:d}): '{1:s}'".format(linenumber, line))

        if len(self.query_rows) == 0:
            raise QueryError("No 'N/S/L/C start end' lines present")
