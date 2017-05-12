# -*- coding: utf-8 -*-
"""
HTTP request handler
"""
from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from future.builtins import *  # NOQA
import sqlite3
import re
import datetime
from obspy import read as mseed_read
from obspy.core.utcdatetime import UTCDateTime
from obspy.core.stream import Stream
import bisect
import uuid
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os.path
import time

import ctypes
from portable_fdsnws_dataselect.msriterator import MSR_iterator

from portable_fdsnws_dataselect import pkg_path, version
from logging import getLogger
from portable_fdsnws_dataselect.request import DataselectRequest, QueryError, NonQueryURLError
from io import BytesIO
import socket
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
class HTTPServer_RequestHandler(BaseHTTPRequestHandler):

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
''' % (code, http_msgs[code], err_msg, '/fdsnws/dataselect/%d/' % version[0], self.format_host(), datetime.datetime.now().isoformat(), version[0], version[1], version[2])
        self.send_response(code)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(bytes(msg, "utf8"))
        logger.error("Code:%d Error:%s Request:%s" % (code, err_msg, self.path))

    def format_host(self, query=''):
        '''Return the fuill URL for this host, w/ query (if provided)
        '''
        path = urlparse(self.path).path
        return "http://%s:%d%s%s" % (self.server.server_name, self.server.server_port, path, query)

    # Direct log messages to common logging
    def log_message(self, format, *args):
        logger.info("%s %s" % (self.address_string(),format%args))

    # GET
    def do_GET(self):
        '''Handle a GET request
        '''
        logger.debug("GET: %s" % self.path)

        try:
            request = DataselectRequest(self.path)
            self.common_process(request)
        except QueryError as e:
            self.return_error(400, str(e))
        except NonQueryURLError as e:
            # Fall back to the basic file-based handler for non-query requests
            self.return_error(404, str(e))

    # POST
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

    def common_process(self, request):
        '''Common processing for both GET and POST requests
        '''

        if request.endpoint == 'version':
            # TODO
            self.return_error(404, "Version")
            return
        elif request.endpoint == 'application.wadl':
            # TODO
            self.return_error(404, "wadl")
            return

        request_time = time.time()
        request_time_str = UTCDateTime(int(request_time)).isoformat() + "Z"

        # Get the corresponding index DB entries
        try:
            index_rows = self.fetch_index_rows(request.query_rows)
        except Exception as err:
            self.return_error(400, str(err))
            return

        total_bytes = 0
        src_bytes = {}

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

        # Gather client information, the reverse DNS lookup could potentially take some time
        client_ip = self.address_string()
        try:
            client_host = socket.gethostbyaddr(client_ip)[0]
        except Exception:
            client_host = client_ip
        user_agent = self.headers.get('User-Agent', '?')

        # Write shipment log
        if self.server.params['shiplogdir']:
            shiplogfile = os.path.join(self.server.params['shiplogdir'],
                                       time.strftime("shipment-%Y-%m-%dZ", time.gmtime(request_time)))

            with open(shiplogfile, "a") as f:
                f.write("START CLIENT %s [%s] @ %s [%s]\n" % (client_host, client_ip, request_time_str, user_agent))

                for srcname in sorted(src_bytes.keys()):
                    f.write("%s %s\n" % (srcname, src_bytes[srcname]))

                f.write("END CLIENT %s [%s] total bytes: %d\n" % (client_host, client_ip, total_bytes))

        logger.info("shipped %d bytes for request %s in %d seconds" % (total_bytes, self.path, duration))

        return

    def fetch_index_rows(self, query_rows):
        '''
        Fetch index rows matching specified request

        `query_rows`: List of tuples containing (net,sta,loc,chan,start,end)

        Request elements may contain '?' and '*' wildcards.  The start and
        end elements can be a single '*' if not a date-time string.

        Return rows as list of tuples containing:
        (network,station,location,channel,quality,starttime,endtime,samplerate,
         filename,byteoffset,bytes,hash,timeindex,timespans,timerates,
         format,filemodtime,updated,scanned,requeststart,requestend)
        '''
        index_rows = []
        my_uuid = uuid.uuid4().hex
        request_table = "request_%s" % my_uuid

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

        # Determine if all_channel_summary table exists
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='all_channel_summary'")
        acs_present = cur.fetchone()[0]

        wildcards = False
        for req in query_rows:
            for field in req:
                if '*' in field or '?' in field:
                    wildcards = True
                    break

        if wildcards:
            # Resolve wildcards using all_channel_summary if present to:
            # a) resolve wildcards, allows use of '=' operator and table index
            # b) reduce index table search to channels that are known included
            if acs_present:
                self.resolve_request(cur, request_table)
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
                   "ORDER BY ts.network,ts.station,ts.location,ts.channel"
                   .format(self.server.params['index_table'],
                           request_table, "GLOB" if wildcards else "=",
                           self.server.params['maxsectiondays']))
            cur.execute(sql)

        except Exception as err:
            import traceback
            traceback.print_exc()
            raise ValueError(str(err))

        index_rows = cur.fetchall()

        cur.execute("DROP TABLE {0}".format(request_table))
        conn.close()

        return index_rows

    def resolve_request(self, cursor, requesttable):
        '''Resolve request table using all_channel_summary
        `cursor`: Database cursor
        `requesttable`: request table to resolve
        Resolve any '?' and '*' wildcards in the specified request table.
        The original table is renamed, rebuilt with a join to all_channel_summary
        and then original table is then removed.
        '''

        requesttable_orig = requesttable + "_orig"

        # Rename request table
        try:
            cursor.execute("ALTER TABLE {0} RENAME TO {1}".format(requesttable, requesttable_orig))
        except Exception as err:
            raise ValueError(str(err))

        # Create resolved request table by joining with all_channel_summary
        try:
            sql = ("CREATE TEMPORARY TABLE {0} "
                   "(network TEXT, station TEXT, location TEXT, channel TEXT, "
                   "starttime TEXT, endtime TEXT) ".format(requesttable))
            cursor.execute(sql)

            sql = ("INSERT INTO {0} (network,station,location,channel,starttime,endtime) "
                   "SELECT s.network,s.station,s.location,s.channel,"
                   "CASE WHEN r.starttime='*' THEN s.earliest ELSE r.starttime END,"
                   "CASE WHEN r.endtime='*' THEN s.latest ELSE r.endtime END "
                   "FROM all_channel_summary s, {1} r "
                   "WHERE "
                   "  (r.starttime='*' OR r.starttime <= s.latest) "
                   "  AND (r.endtime='*' OR r.endtime >= s.earliest) "
                   "  AND (r.network='*' OR s.network GLOB r.network) "
                   "  AND (r.station='*' OR s.station GLOB r.station) "
                   "  AND (r.location='*' OR s.location GLOB r.location) "
                   "  AND (r.channel='*' OR s.channel GLOB r.channel) ".format(requesttable, requesttable_orig))
            cursor.execute(sql)

        except Exception as err:
            raise ValueError(str(err))

        resolvedrows = cursor.execute("SELECT COUNT(*) FROM {0}".format(requesttable)).fetchone()[0]

        cursor.execute("DROP TABLE {0}".format(requesttable_orig))
