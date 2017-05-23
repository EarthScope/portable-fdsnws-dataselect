# -*- coding: utf-8 -*-
"""
HTTP request handler
"""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from future.standard_library import install_aliases
install_aliases()
from future.builtins import *  # NOQA
from future.backports.http.server import SimpleHTTPRequestHandler

import os.path
import time
import re
import datetime
import sqlite3
import uuid
import socket

from logging import getLogger, DEBUG
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, urlencode
from collections import namedtuple
from obspy.core.utcdatetime import UTCDateTime
from obspy.core.stream import Stream
from portable_fdsnws_dataselect import pkg_path, version
from portable_fdsnws_dataselect.request import DataselectRequest, QueryError, NonQueryURLError
from portable_fdsnws_dataselect.miniseed import NoDataError, RequestLimitExceededError

logger = getLogger(__name__)

# Mapping of HTTP code to short descriptions
http_msgs = {
    200: "Successful request, results follow",
    204: "Request was properly formatted and submitted but no data matches the selection",
    400: "Bad request",
    401: "Unauthorized, authentication required",
    403: "Authentication failed or access blocked to restricted data",
    404: "Request was properly formatted and submitted but no data matches the selection",
    413: "Request would result in too much data being returned or the request itself is too large",
    414: "Request URI too large",
    500: "Internal server error",
    503: "Service temporarily unavailable"
}


# HTTPRequestHandler class
class HTTPServer_RequestHandler(SimpleHTTPRequestHandler):

    prefix = '/fdsnws/dataselect/%d/' % version[0]

    def do_HEAD(self):
        ''' Send response code & header for normal/successful response '''
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_AUTHHEAD(self):
        ''' Send response code & header for authentication-request response '''
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'basic realm=\"FDSNWS\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def return_error(self, code, err_msg):
        '''An error has occurred (code # code, details in err_msg)

        Log it, return message page
        '''
        msg = '''Error %d: %s

%s

Usage details are available from %s

Request:
%s

Request Submitted:
%s

Service version:
Service: fdsnws-dataselect  version %d.%d.%d
''' % (code, http_msgs[code], err_msg, self.prefix, self.format_host(),
       datetime.datetime.now().isoformat(), version[0], version[1], version[2])
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(msg.encode("utf8"))
        logger.error("Code:%d Error:%s Request:%s" % (code, err_msg, self.path))

    def return_version(self):
        """
        Return service version information
        """
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        message = "%d.%d.%d\n" % version
        self.wfile.write(message.encode("utf8"))

    def return_wadl(self):
        """
        Return application.wadl
        """
        self.send_response(200)
        self.send_header('Content-type', 'application/xml')
        self.end_headers()
        server_port = ""
        if self.server.server_port != 80:
            server_port = ":%d" % self.server.server_port
        base_url = "http://%s%s%s" % (
            self.server.server_name, server_port, self.prefix
        )
        with open(os.path.join(os.path.dirname(pkg_path), 'docs', 'application.wadl'), 'r') as f:
            # Note we need to substitute the base URL into the wadl
            message = f.read() % base_url
            self.wfile.write(message.encode("utf8"))

    def format_host(self, query=''):
        '''Return the full URL for this host, w/ query (if provided)
        '''
        path = urlparse(self.path).path
        return "http://%s:%d%s%s" % (self.server.server_name, self.server.server_port, path, query)

    # Direct log messages to common logging
    def log_message(self, format, *args):
        logger.info("%s %s" % (self.address_string(), format % args))

    def do_GET(self):
        '''Handle a GET request
        '''
        logger.debug("GET: %s" % self.path)

        try:
            request = DataselectRequest(self.path)
            self.common_process(request)
        except QueryError as e:
            self.return_error(400, str(e))
        except NonQueryURLError:
            self.handle_nonquery()

    def do_POST(self):
        '''Handle a POST request
        '''
        logger.debug("POST: %s" % self.path)

        request_text = self.rfile.read(int(self.headers['Content-Length'])).decode("utf-8")

        logger.debug("POST query:\n%s" % request_text)

        try:
            request = DataselectRequest(self.path, request_text)
            self.common_process(request)
        except QueryError as e:
            self.return_error(400, str(e))
        except NonQueryURLError:
            self.return_error(404, "File not found")

    def common_process(self, request):
        '''Common processing for both GET and POST requests
        '''

        if request.endpoint == 'version':
            self.return_version()
            return
        elif request.endpoint == 'application.wadl':
            self.return_wadl()
            return
        elif request.endpoint == 'summary':
            summary_rows = self.fetch_summary_rows(request.query_rows)

            self.send_response(200)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()

            summary = "#{0:<7s}{1:<8s}{2:<8s}{3:<8s}{4:<28s}{5:<28s}{6:<20s}\n".format(
                "Net", "Sta", "Loc", "Chan", "Earliest", "Latest", "Updated")
            self.wfile.write(summary.encode("utf8"))

            for NRow in summary_rows:
                loc = NRow.location if NRow.location != '' else '--'
                summary_row = "{0:<8s}{1:<8s}{2:<8s}{3:<8s}{4:<28s}{5:<28s}{6:<20s}\n".format(
                    NRow.network, NRow.station, loc, NRow.channel,
                    NRow.earliest, NRow.latest, NRow.updated)
                self.wfile.write(summary_row.encode("utf8"))
            return
        elif request.endpoint == 'queryauth':
            self.return_error(403, "Authorization via the 'queryauth' endpoint not implemented")

            # The code stubs below remains for future reference.
            # Per the FDSN spec, HTTP Digest Authorization is required,
            # not the HTTP Basic Authorization below.
            key = self.server.get_auth_key()
            if self.headers.get('Authorization') is None:
                # Need authorization
                self.do_AUTHHEAD()
                self.wfile.write('No auth header received'.encode("utf8"))
                return
            elif self.headers.get('Authorization') != 'Basic ' + str(key):
                # Improper authorization sent; inform client
                self.do_AUTHHEAD()
                self.wfile.write('Invalid credentials'.encode("utf8"))
                return
            # Otherwise, authentication is valid and we can fall through to the normal request handling

        request_time = time.time()
        request_time_str = UTCDateTime(int(request_time)).isoformat() + "Z"

        if logger.isEnabledFor(DEBUG):
            for key in request.bulk_params.keys():
                logger.debug("REQUEST: %s = %s" % (key, request.bulk_params[key]))
            for row in request.query_rows:
                logger.debug("REQUEST: %s" % " ".join(row))

        # Get the corresponding index DB entries
        try:
            index_rows = self.fetch_index_rows(request.query_rows, request.bulk_params)
        except Exception as err:
            self.return_error(400, str(err))
            return

        total_bytes = 0
        src_bytes = {}

        logger.debug("Starting data return")

        try:
            # Extract the data, writing each returned segment to the response
            for data_segment in self.server.data_extractor.extract_data(index_rows):
                shipped_bytes = data_segment.get_num_bytes()
                src_name = data_segment.get_src_name()
                if shipped_bytes > 0:
                    # If this is the first segment to be written, add the response headers first
                    if total_bytes == 0:
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/vnd.fdsn.mseed')
                        self.send_header('Content-Disposition',
                                         'attachment; filename=fdsnws-dataselect_%s.mseed' % request_time_str)
                        self.end_headers()
                    data_segment.write(self.wfile)
                    total_bytes += shipped_bytes
                    src_bytes.setdefault(src_name, 0)
                    src_bytes[src_name] += shipped_bytes
        except NoDataError:
            self.return_error(int(request.bulk_params['nodata']), "No data matched selection")
            return False
        except RequestLimitExceededError as limit_err:
            self.return_error(413, str(limit_err))
            return False
        except Exception as err:
            self.return_error(500, str(err))
            return False

        duration = time.time() - request_time

        # Write shipment log
        if self.server.params['shiplogdir']:
            # Gather client information, the reverse DNS lookup could potentially take some time
            client_ip = self.address_string()
            try:
                client_host = socket.gethostbyaddr(client_ip)[0]
            except Exception:
                client_host = client_ip
            user_agent = self.headers.get('User-Agent', '?')
            shiplogfile = os.path.join(self.server.params['shiplogdir'],
                                       time.strftime("shipment-%Y-%m-%dZ", time.gmtime(request_time)))
            logger.debug("Writing shipment log to %s" % shiplogfile)

            with open(shiplogfile, "a") as f:
                f.write("START CLIENT %s [%s] @ %s [%s]\n" % (client_host, client_ip, request_time_str, user_agent))

                for srcname in sorted(src_bytes.keys()):
                    f.write("%s %s\n" % (srcname, src_bytes[srcname]))

                f.write("END CLIENT %s [%s] total bytes: %d\n" % (client_host, client_ip, total_bytes))

        logger.info("shipped %d bytes for request %s in %d seconds" % (total_bytes, self.path, duration))

        return

    def fetch_index_rows(self, query_rows, bulk_params):
        '''
        Fetch index rows matching specified request

        `query_rows`: List of tuples containing (net,sta,loc,chan,start,end)
        `bulk_params`: Dict of bulk parameters (e.g. quality, minsegmentlength)

        Request elements may contain '?' and '*' wildcards.  The start and
        end elements can be a single '*' if not a date-time string.

        Return rows as list of named tuples containing:
        (network,station,location,channel,quality,starttime,endtime,samplerate,
         filename,byteoffset,bytes,hash,timeindex,timespans,timerates,
         format,filemodtime,updated,scanned,requeststart,requestend)
        '''
        my_uuid = uuid.uuid4().hex
        request_table = "request_%s" % my_uuid

        logger.debug("Opening SQLite database for index rows: %s" % self.server.params['dbfile'])

        try:
            conn = sqlite3.connect(self.server.params['dbfile'], 10.0)
        except Exception as err:
            raise ValueError(str(err))

        cur = conn.cursor()

        # Store temporary table(s) in memory
        try:
            cur.execute("PRAGMA temp_store=MEMORY")
        except Exception as err:
            raise ValueError(str(err))

        # Create temporary table and load request
        try:
            cur.execute("CREATE TEMPORARY TABLE {0} "
                        "(network TEXT, station TEXT, location TEXT, channel TEXT, "
                        "starttime TEXT, endtime TEXT) ".format(request_table))

            for req in query_rows:
                # Replace "--" location ID request alias with true empty value
                if req[2] == "--":
                    req[2] = ""

                cur.execute("INSERT INTO {0} (network,station,location,channel,starttime,endtime) "
                            "VALUES (?,?,?,?,?,?) ".format(request_table), req)

        except Exception as err:
            import traceback
            traceback.print_exc()
            raise ValueError(str(err))

        # Determine if summary table exists, default to index_summary
        if 'summary_table' in self.server.params:
            summary_table = self.server.params['summary_table']
        else:
            summary_table = "{0}_summary".format(self.server.params['index_table'])
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='{0}'".format(summary_table))
        summary_present = cur.fetchone()[0]

        wildcards = False
        for req in query_rows:
            for field in req:
                if '*' in field or '?' in field:
                    wildcards = True
                    break

        if wildcards:
            # Resolve wildcards using summary if present to:
            # a) resolve wildcards, allows use of '=' operator and table index
            # b) reduce index table search to channels that are known included
            if summary_present:
                self.resolve_request(cur, summary_table, request_table)
                wildcards = False
            # Replace wildcarded starttime and endtime with extreme date-times
            else:
                cur.execute("UPDATE {0} SET starttime='0000-00-00T00:00:00' WHERE starttime='*'".format(request_table))
                cur.execute("UPDATE {0} SET endtime='5000-00-00T00:00:00' WHERE endtime='*'".format(request_table))

        # Fetch final results by joining resolved and index table
        try:
            sql = ("SELECT DISTINCT ts.network,ts.station,ts.location,ts.channel,ts.quality, "
                   "ts.starttime,ts.endtime,ts.samplerate, "
                   "ts.filename,ts.byteoffset,ts.bytes,ts.hash, "
                   "ts.timeindex,ts.timespans,ts.timerates, "
                   "ts.format,ts.filemodtime,ts.updated,ts.scanned, r.starttime, r.endtime "
                   "FROM {0} ts, {1} r "
                   "WHERE "
                   "  ts.network {2} r.network "
                   "  AND ts.station {2} r.station "
                   "  AND ts.location {2} r.location "
                   "  AND ts.channel {2} r.channel "
                   "  AND ts.starttime <= r.endtime "
                   "  AND ts.starttime >= datetime(r.starttime,'-{3} days') "
                   "  AND ts.endtime >= r.starttime "
                   .format(self.server.params['index_table'],
                           request_table, "GLOB" if wildcards else "=",
                           self.server.params['maxsectiondays']))

            # Add quality identifer criteria
            if 'quality' in bulk_params and bulk_params['quality'] in ('D', 'R', 'Q'):
                sql = sql + " AND quality = '{0}' ".format(bulk_params['quality'])

            cur.execute(sql)

        except Exception as err:
            import traceback
            traceback.print_exc()
            raise ValueError(str(err))

        # Map raw tuples to named tuples for clear referencing
        NamedRow = namedtuple('NamedRow',
                              ['network', 'station', 'location', 'channel', 'quality',
                               'starttime', 'endtime', 'samplerate', 'filename',
                               'byteoffset', 'bytes', 'hash', 'timeindex', 'timespans',
                               'timerates', 'format', 'filemodtime', 'updated', 'scanned',
                               'requeststart', 'requestend'])

        index_rows = []
        while True:
            row = cur.fetchone()
            if row is None:
                break
            index_rows.append(NamedRow(*row))

        # Sort results in application (ORDER BY in SQL triggers bad index usage)
        index_rows.sort()

        logger.debug("Fetched %d index rows" % len(index_rows))

        cur.execute("DROP TABLE {0}".format(request_table))
        conn.close()

        return index_rows

    def resolve_request(self, cursor, summary_table, request_table):
        '''Resolve request table using summary
        `cursor`: Database cursor
        `summary_table`: summary table to resolve with
        `request_table`: request table to resolve
        Resolve any '?' and '*' wildcards in the specified request table.
        The original table is renamed, rebuilt with a join to summary
        and then original table is then removed.
        '''

        request_table_orig = request_table + "_orig"

        # Rename request table
        try:
            cursor.execute("ALTER TABLE {0} RENAME TO {1}".format(request_table, request_table_orig))
        except Exception as err:
            raise ValueError(str(err))

        # Create resolved request table by joining with summary
        try:
            sql = ("CREATE TEMPORARY TABLE {0} "
                   "(network TEXT, station TEXT, location TEXT, channel TEXT, "
                   "starttime TEXT, endtime TEXT) ".format(request_table))
            cursor.execute(sql)

            sql = ("INSERT INTO {0} (network,station,location,channel,starttime,endtime) "
                   "SELECT s.network,s.station,s.location,s.channel,"
                   "CASE WHEN r.starttime='*' THEN s.earliest ELSE r.starttime END,"
                   "CASE WHEN r.endtime='*' THEN s.latest ELSE r.endtime END "
                   "FROM {1} s, {2} r "
                   "WHERE "
                   "  (r.starttime='*' OR r.starttime <= s.latest) "
                   "  AND (r.endtime='*' OR r.endtime >= s.earliest) "
                   "  AND (r.network='*' OR s.network GLOB r.network) "
                   "  AND (r.station='*' OR s.station GLOB r.station) "
                   "  AND (r.location='*' OR s.location GLOB r.location) "
                   "  AND (r.channel='*' OR s.channel GLOB r.channel) ".
                   format(request_table, summary_table, request_table_orig))
            cursor.execute(sql)

        except Exception as err:
            raise ValueError(str(err))

        resolvedrows = cursor.execute("SELECT COUNT(*) FROM {0}".format(request_table)).fetchone()[0]

        logger.debug("Resolved request with summary into %d rows" % resolvedrows)

        cursor.execute("DROP TABLE {0}".format(request_table_orig))

        return resolvedrows

    def fetch_summary_rows(self, query_rows):
        '''
        Fetch summary rows matching specified request

        `query_rows`: List of tuples containing (net,sta,loc,chan,start,end)

        Request elements may contain '?' and '*' wildcards.  The start and
        end elements can be a single '*' if not a date-time string.

        Return rows as list of named tuples containing:
        (network,station,location,channel,earliest,latest,updated)
        '''
        summary_rows = []
        my_uuid = uuid.uuid4().hex
        request_table = "request_%s" % my_uuid

        logger.debug("Opening SQLite database for summary rows: %s" % self.server.params['dbfile'])

        try:
            conn = sqlite3.connect(self.server.params['dbfile'], 10.0)
        except Exception as err:
            raise ValueError(str(err))

        cur = conn.cursor()

        # Store temporary table(s) in memory
        try:
            cur.execute("PRAGMA temp_store=MEMORY")
        except Exception as err:
            raise ValueError(str(err))

        # Create temporary table and load request
        try:
            cur.execute("CREATE TEMPORARY TABLE {0} "
                        "(network TEXT, station TEXT, location TEXT, channel TEXT)".
                        format(request_table))

            for req in query_rows:
                # Replace "--" location ID request alias with true empty value
                if req[2] == "--":
                    req[2] = ""

                cur.execute("INSERT INTO {0} (network,station,location,channel) "
                            "VALUES (?,?,?,?) ".format(request_table), req[:4])

        except Exception as err:
            import traceback
            traceback.print_exc()
            raise ValueError(str(err))

        # Determine if summary table exists, default to index_summary
        if 'summary_table' in self.server.params:
            summary_table = self.server.params['summary_table']
        else:
            summary_table = "{0}_summary".format(self.server.params['index_table'])
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='{0}'".format(summary_table))
        summary_present = cur.fetchone()[0]

        if summary_present:
            # Select summary rows by joining with summary table
            try:
                sql = ("SELECT DISTINCT s.network,s.station,s.location,s.channel,"
                       "s.earliest,s.latest,s.updt "
                       "FROM {0} s, {1} r "
                       "WHERE "
                       "  (r.network='*' OR s.network GLOB r.network) "
                       "  AND (r.station='*' OR s.station GLOB r.station) "
                       "  AND (r.location='*' OR s.location GLOB r.location) "
                       "  AND (r.channel='*' OR s.channel GLOB r.channel) ".
                       format(summary_table, request_table))
                cur.execute(sql)

            except Exception as err:
                raise ValueError(str(err))

            # Map raw tuples to named tuples for clear referencing
            NamedRow = namedtuple('NamedRow',
                                  ['network', 'station', 'location', 'channel',
                                   'earliest', 'latest', 'updated'])

            summary_rows = []
            while True:
                row = cur.fetchone()
                if row is None:
                    break
                summary_rows.append(NamedRow(*row))

            # Sort results in application (ORDER BY in SQL triggers bad index usage)
            summary_rows.sort()

            logger.debug("Fetched %d summary rows" % len(summary_rows))

            cur.execute("DROP TABLE {0}".format(request_table))
            conn.close()

        return summary_rows

    def handle_nonquery(self):
        """
        Handle a request that doesn't correspond to any service endpoint by falling back to standard
        web server behavior, returning static files from a configured directory.

        The wrinkle here is that the document directory is mapped to the base service path
        (ie. /fdsnws/dataselect/1/), so for example a document stored at
        $docroot/help/questions.html
        would appear at
        /fdsnws/dataselect/1/help/questions.html

        A request to a URL not under the base service path will be redirected to the base path.

        This is intended as a quick and dirty alternative to setting up a dedicated web server like Apache.
        If more complex behavior is required, a dedicated server should be used instead.
        """
        # If the request was totally outside the service prefix, redirect to the prefix
        request_path = urlparse(self.path).path
        if not request_path.startswith(self.prefix):
            self.send_response(301)
            self.send_header("Location", self.prefix)
            self.end_headers()
        # Otherwise, fall back to handling this using `SimpleHTTPRequestHandler`
        else:
            # This is the guts of `SimpleHTTPRequestHandler.do_GET`
            f = self.send_head()
            if f:
                self.copyfile(f, self.wfile)
                f.close()

    def translate_path(self, path):
        """
        This is part of `SimpleHTTPRequestHandler` that gets called to serve static files by `handle_nonquery`.

        This translates a URL path into a filesystem path.
        We want to strip off the URL prefix (ie. "/fdsnws/dataselect/1/") and make the rest of the URL
        path relative to the configured docroot.
        """
        docroot = self.server.params['docroot'] or os.path.join(os.path.dirname(pkg_path), "docs")
        relative_paths = self.path[len(self.prefix):].split('/')
        return os.path.join(docroot, *relative_paths)

    def list_directory(self, path):
        """
        This is part of `SimpleHTTPRequestHandler` that gets called to serve static files by `handle_nonquery`.

        By default, `SimpleHTTPRequestHandler` will list the contents of a directory if there isn't
        an index file. This is a security risk, so this reverses the default to return a 404 unless specifically
        configured.
        """
        if self.server.params['show_directories']:
            return super(HTTPServer_RequestHandler, self).list_directory(path)
        else:
            self.send_error(404, "No permission to list directory")
            return None
