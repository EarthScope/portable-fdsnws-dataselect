from socketserver import ThreadingMixIn
from queue import Queue
import threading, socket, datetime, configparser
import sqlite3, re, configparser, sys, os, io
from obspy import read as mseed_read
from obspy.core.utcdatetime import UTCDateTime
from obspy.core.stream import Stream
import logging
import logging.config
import bisect
import uuid, base64
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import os.path
 

version = (1,1,0)
logger = None

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

def normalize_datetime(timestring):
    '''Normalize time string to strict YYYY-MM-DDThh:mm:ss.ffffff format
    '''

    # Split Year,Month,Day Hour,Min,Second,Fractional seconds
    timepieces = re.split("[-.:T]+", timestring)
    timepieces = [int(i) for i in timepieces]

    # Rebuild into target format
    return datetime.datetime(*timepieces).strftime("%Y-%m-%dT%H:%M:%S.%f")

class ThreadPoolMixIn(ThreadingMixIn):
    '''
    use a thread pool instead of a new thread on every request
    '''
    numThreads = 10
    allow_reuse_address = True  # seems to fix socket.error on server restart

    def serve_forever(self):
        '''
        Handle one request at a time until doomsday.
        '''
        # set up the threadpool
        self.requests = Queue(self.numThreads)

        for x in range(self.numThreads):
            t = threading.Thread(target = self.process_request_thread)
            t.setDaemon(1)
            t.start()

        # server main loop
        while True:
            self.handle_request()
            
        self.server_close()

    
    def process_request_thread(self):
        '''
        obtain request from queue instead of directly from server socket
        '''
        while True:
            ThreadingMixIn.process_request_thread(self, *self.requests.get())

    
    def handle_request(self):
        '''
        simply collect requests and put them on the queue for the workers.
        '''
        try:
            request, client_address = self.get_request()
        except socket.error:
            return
        if self.verify_request(request, client_address):
            self.requests.put((request, client_address))

# HTTPRequestHandler class
class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):
 
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

    def return_error( self, code, err_msg ):
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
%d.%d.%d
''' % (code, http_msgs[code], err_msg, "doc uri", self.format_host(), datetime.datetime.now().isoformat(), version[0], version[1], version[2])
        self.send_error(code, msg)
        logger.error( "Code:%d Error:%s Request:%s" % (code, err_msg, self.path) )

    def format_host( self, query='' ):
        '''Return the fuill URL for this host, w/ query (if provided)
        '''
        return "http://%s:%d%s%s" % (self.server.server_name, self.server.server_port, self.fdsnws_req.path, query)
        
    def parse_fdsnws_url( self, get_call ):
        '''Parse the request in self.fdsnws_req, and do some validation.
        
        Return "Request needs to be processed"
        '''
        req = self.fdsnws_req
        prefix = '/fdsnws/dataselect/%d/'%version[0]
        if not req.path.lower().startswith(prefix):
            self.return_error( 400, 'URL path must begin with "{0}"'.format(prefix) )
            return False
            
        # Check that it begins with /fdsnws/dataselect/1/
        # followed by either:
        #   query
        #   queryauth
        #   version
        #   application.wadl
        path_tail = req.path.lower()[len(prefix):]
        if get_call:
            if path_tail not in ('query','queryauth','version','application.wadl'):
                self.return_error( 400, 'GET URL path must end with /query, /queryauth, /version or /application.wadl' )
                return False
        else:
            if path_tail not in ('query','queryauth'):
                self.return_error( 400, 'POST URL path must end with /query or /queryauth' )
                return False

        # Send response status code
        if path_tail in ('version','application.wadl'):
            self.send_response(200)
 
            # Send headers; determine message to back to client
            if path_tail == 'version':
                self.send_header('Content-type','text/plain')
                message = "%d.%d.%d\n" % version
            else:
                self.send_header('Content-type','application/xml')
                message = '''%s?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <application xmlns="http://wadl.dev.java.net/2009/02">
    <doc title="FDSN dataselect web service 1.0"/>
    <grammars/>
    <resources base="%s">
        <resource path="/">
            <method name="GET" id="root">
                <response>
                    <representation mediaType="text/html"/>
                </response>
            </method>
            <resource path="query">
                <method name="GET" id="query">
		    <request>
		      <param name="starttime" style="query" required="true" type="xs:date"/>
		      <param name="endtime" style="query" required="true" type="xs:date"/>
		      <param name="network" style="query"  type="xs:string"/>
		      <param name="station" style="query"  type="xs:string"/>
		      <param name="location" style="query" type="xs:string"/>
		      <param name="channel" style="query" type="xs:string"/>
		      <param name="quality" style="query" type="xs:string" default="B">
                               <option value="D"/>
                               <option value="R"/>
                               <option value="Q"/>
                               <option value="M"/>
                               <option value="B"/>
                      </param>
		      <param name="minimumlength" style="query" type="xs:double" default="0.0"/>
		      <param name="longestonly" style="query" type="xs:boolean" default="false"/>
		      <param name="format" style="query" type="xs:string" default="miniseed"/>
		    </request>
                    <response>
                      <representation mediaType="text/plain"/>
                      <representation mediaType="application/vnd.fdsn.mseed"/>
                    </response>
                </method>
                <method name="POST" id="postQuery">
                    <request>
                      <representation mediaType="*/*"/>
                    </request>
                    <response>
                      <representation mediaType="text/plain"/>
                      <representation mediaType="application/vnd.fdsn.mseed"/>
                    </response>
                </method>
            </resource>
            <resource path="queryauth">
                <method name="GET" id="queryAuth">
		    <request>
		      <param name="starttime" style="query" required="true" type="xs:date"/>
		      <param name="endtime" style="query" required="true" type="xs:date"/>
		      <param name="network" style="query" type="xs:string"/>
		      <param name="station" style="query" type="xs:string"/>
		      <param name="location" style="query" type="xs:string"/>
		      <param name="channel" style="query" type="xs:string"/>
		      <param name="quality" style="query" type="xs:string" default="B">
                               <option value="D"/>
                               <option value="R"/>
                               <option value="Q"/>
                               <option value="M"/>
                               <option value="B"/>
                      </param>
		      <param name="minimumlength" style="query" type="xs:double" default="0.0"/>
		      <param name="longestonly" style="query" type="xs:boolean" default="false"/>
		      <param name="format" style="query" type="xs:string" default="miniseed"/>
		    </request>
                    <response>
                      <representation mediaType="text/plain"/>
                      <representation mediaType="application/vnd.fdsn.mseed"/>
                    </response>
                </method>
                <method name="POST" id="postQueryAuth">
                    <request>
                        <representation mediaType="*/*"/>
                    </request>
                    <response>
                      <representation mediaType="text/plain"/>
                      <representation mediaType="application/vnd.fdsn.mseed"/>
                    </response>
                </method>
            </resource>
            <resource path="version">
                <method name="GET" id="version">
                    <response>
                      <representation mediaType="text/plain"/>
                    </response>
                </method>
            </resource>
            <resource path="application.wadl">
                <method name="GET" id="application.wadl">
                    <response>
                      <representation mediaType="application/xml"/>
                    </response>
                </method>
            </resource>
        </resource>
    </resources>
</application>
''' % ("<",self.format_host())
            self.end_headers()

                
            # Write content as utf-8 data)
            self.wfile.write(bytes(message, "utf8"))
            return False
        
        if path_tail == 'queryauth':
            key = self.server.get_auth_key()
            ''' Present frontpage with user authentication. '''
            if self.headers.get('Authorization') == None:
                self.do_AUTHHEAD()
                self.wfile.write(bytes('No auth header received',"utf8") );        
                return False

            elif self.headers.get('Authorization') == 'Basic ' + str(key):
                # Request is properly authorized; let caller process request   
                return True   
            else:
                # Improper authorization sent; inform client
                self.do_AUTHHEAD()
                self.wfile.write(bytes('Invalid credentials',"utf8") );
                return False
            
        return True              
        
    def build_get_where( self, ds_args ):
        '''Build the WHERE clause for a SELECT statement to get the data described in ds_args
        '''
        sql_args = dict()
        other_args = dict()
        for k,v in ds_args.items():
            if k in ( 'starttime', 'endtime' ):
                sql_args[k] = v
            elif k == 'quality':
                sql_args[k] = v
            elif k in ('network','station','location','channel'):
                sql_args[k] = []
                for vv in [x.strip() for x in v.split(",")]:
                    if k=='location' and vv == '--':
                        vv = ''
                    sql_args[k].append( '%s GLOB "%s"' % (k,vv) )
            elif k in ('format','nodata','minimumlength','longestonly'):
                other_args[k] = v
                
        conj = []
        if 'starttime' in sql_args:
            conj.append( 'endtime >= "%s"' % sql_args['starttime'] )
        if 'endtime' in sql_args:
            conj.append( 'starttime <= "%s"' % sql_args['endtime'] )
        for k in ('network','station','location','channel'):
            if k in sql_args:
                conj.append( " OR ".join( sql_args[k] ))
        if 'quality' in sql_args:
            conj.append( " OR ".join( ['quality = "%s"' % v for v in sql_args['quality']] ))
        return (" AND ".join( ["(%s)" % x for x in conj] ), other_args)

    def handle_trimming( self, stime, etime, row ):
        '''Get the time & byte-offsets for the data in time range (stime, etime)
        
        This is done by finding the smallest section of the data in row that falls within the desired time range
        and is identified by the timindex field of row
        
        Return [(start time, start offset),(end_time,end_offset)]
        '''
        row_stime = UTCDateTime( row[5] )
        row_etime = UTCDateTime( row[6] )

        # If we need a subset of the this block, trim it accordingly
        block_start = int(row[9])
        block_end = block_start + int(row[10])
        if stime > row_stime or etime < row_etime:
            tix = [x.split("=>") for x in row[11].split(",")]
            if tix[-1][0]=='latest':
                tix[-1] = [str(row_etime.timestamp),block_end]
            to_x = [float(x[0]) for x in tix]
            s_index = bisect.bisect_right( to_x, stime.timestamp )-1
            if s_index < 0:
                s_index = 0
            e_index = bisect.bisect_right( to_x, etime.timestamp )
            off_start = int(tix[s_index][1])
            if e_index >= len(tix):
                e_index = -1
            off_end = int(tix[e_index][1])
            return ([to_x[s_index],off_start], [to_x[e_index],off_end])
        else:
            return ([row_stime.timestamp,block_start], [row_etime.timestamp,block_end])       
        
    def process_get_request( self, req, outstream ):
        '''Given the query arguments in req, write the requested mseed data to outstream.
        
        Return "was successful"
        '''
        cols = ['network', 'station', 'location', 'channel', 'quality', 'starttime', 'endtime', 'samplerate', 'filename', 'byteoffset', 'bytes', 'timeindex']
        stime = UTCDateTime( req['starttime'] )
        etime = UTCDateTime( req['endtime'] )
        where_clause,other_args = self.build_get_where( req )
        traces = []

        try:
            conn = sqlite3.connect( self.server._db_path, 10.0 )
        except Exception as err:
            self.return_error( 500, "Could not connect to DB: %s" % str(err) )
            return False

        c = conn.cursor()
        c.execute( "PRAGMA case_sensitive_like=ON;" )
        sql = "SELECT %s from %s WHERE %s ORDER BY filename, byteoffset" % (",".join(cols),self.server._index_table,where_clause)
        total_bytes = 0
        try:
            for row in c.execute( sql ):
                trim_info = self.handle_trimming( stime, etime, row )
                with open( row[8], "rb" ) as f:
                    f.seek( trim_info[0][1] )
                    fb = io.BytesIO( f.read( trim_info[1][1]-trim_info[0][1] ) )
                st = mseed_read(fb)
                tr = st[0]
                if tr.stats.sampling_rate>0:
                    tr.trim( stime, etime )
                if tr.stats.npts > 0:
                    traces.append( tr )
                    total_bytes += tr.stats.mseed['filesize']
                    if total_bytes > self.server._output_cap:
                        self.return_error( 413, "Result exceeds cap of %d bytes" % self.server._output_cap)
                        return False

        except Exception as err:
            import traceback
            traceback.print_exc()
            self.return_error( 500, "Error accessing data: %s" % str(err) )
            return False
            
        if len(traces)==0:
            self.return_error( int(req['nodata']), "No data matched slection" )
            return False

        logger.debug("Data identified (%d bytes)" % total_bytes)
        try:
            st = Stream( traces=traces )
            st.write( outstream, format="MSEED" )
        except Exception as err:
            import traceback
            traceback.print_exc()
            self.return_error( 500, "Error returning mseed data: %s" % str(err) )
            return False

        logger.info( "%d bytes transferred for request %s" % (total_bytes, self.path) )
        return True
                   
    # GET
    def do_GET(self):
        '''Handle a GET request
        '''
        logger.info( "GET: %s" % self.path )

        self.fdsnws_req = req = urlparse(self.path)
        
        if not self.parse_fdsnws_url(True):
            return
                    
        qry = parse_qs( req.query )
        supported = ('starttime','endtime','network','station','location','channel','quality','minimumlength','longestonly','format','nodata')
        sql_qry = dict( starttime=['1970-01-01'], endtime=['2170-12-31T23:59:59.999999'], format=['miniseed'], nodata=['204'],
                        network=['*'], station=['*'], location=['*'], channel=['*'], quality=['B'], minimumlength=['0.0'], longestonly=['FALSE'] )
        abbreviations = {'start':'starttime', 'end':'endtime', 'loc':'location', 'net':'network', 'sta':'station', 'cha':'channel'}
        for k,v in qry.items():
            k = abbreviations.get( k, k )
            if k not in supported:
                self.return_error( 400, "Unrecognized query parameter: '%s'" % k )
                return
            elif len(v)>1:
                self.return_error( 400, "Multiple '%s' parameters not allowed." % k )
                return
            else:
                v = v[0]
                if k.endswith('time'):
                    try:
                        datetime.datetime.strptime( v, "%Y-%m-%dT%H:%M:%S.%f" )
                    except:
                        try:
                            datetime.datetime.strptime( v, "%Y-%m-%dT%H:%M:%S" )
                        except:
                            try:
                                datetime.datetime.strptime( v, "%Y-%m-%d" )
                            except:
                                self.return_error( 400, "Required format for '%s' one of YYYY-MM-DDTHH:MM:SS.ssssss, YYYY-MM-DDTHH:MM:SS or YYYY-MM-DD" % k )
                elif k == 'quality':
                    if v not in ('D', 'R', 'Q', 'M', 'B'):
                        self.return_error( 400, "quality must be one of B, D, R, M or Q" )
                        return
                elif k == 'minimumlength':
                    try:
                        if float(v) < 0:
                            raise
                    except:
                        self.return_error( 400, "minimumlength must be a non-negative number" )
                        return
                elif k == 'longestonly':
                    if v.upper() not in ('TRUE','FALSE'):
                        self.return_error( 400, "longestonly must be either TRUE or FALSE" )
                        return
                    v = v.upper()
                elif k == 'format':
                    if v.lower() not in ('miniseed','text','xml'):
                        self.return_error( 400, "Unsupported format: '%s'" % v )
                        return
                sql_qry[k] = [v]

        # Send response status code
        self.send_response(200)
 
        # Send headers
        if sql_qry['format']=='miniseed':
            self.send_header('Content-type','application/vnd.fdsn.mseed')
        elif sql_qry['format']=='text':
            self.send_header('Content-type','text/plain')
        self.end_headers()
 
        if not self.process_get_request( {k:v[0] for k,v in sql_qry.items()}, self.wfile ):
            return
            
        return
 
    # POST
    def do_POST(self):
        '''Handle a POST request
        '''
        logger.info( "POST: %s" % self.path )
        self.fdsnws_req = req = urlparse(self.path)

        if not self.parse_fdsnws_url(True):
            return

        try:
            prefix, request = self.read_request_file()
        except Exception as err:
            self.return_error( 400, str(err) )
            return
            
        print(request)
        try:
            index_rows = self.fetch_index_rows( prefix, request )
        except Exception as err:
            self.return_error( 400, str(err) )
            return

        traces = []
        total_bytes = 0
        try:
            for row in index_rows:
                stime = UTCDateTime( row[5] )
                etime = UTCDateTime( row[6] )
                trim_info = self.handle_trimming( stime, etime, row )
                bytes = trim_info[1][1]-trim_info[0][1]
                
                with open( row[8], "rb" ) as f:
                    f.seek( trim_info[0][1] )
                    fb = io.BytesIO( f.read( bytes ) )
                st = mseed_read(fb)
                tr = st[0]
                if tr.stats.sampling_rate>0:
                    tr.trim( stime, etime )
                if tr.stats.npts > 0:
                    traces.append( tr )
                    total_bytes += tr.stats.mseed['filesize']
                    if total_bytes > self.server._output_cap:
                        self.return_error( 413, "Result exceeds cap of %d bytes" % self.server._output_cap)
                        return False
        except Exception as err:
            self.return_error( 500, "Error accessing data: %s" % str(err) )
            return False
            
        if len(traces)==0:
            self.return_error( int(req['nodata']), "No data matched slection" )
            return False

        # Send response status code
        self.send_response(200)
 
        # Send headers
        self.send_header('Content-type','application/vnd.fdsn.mseed')
        self.end_headers()
 
        try:
            st = Stream( traces=traces )
            st.write( self.wfile, format="MSEED" )
        except Exception as err:
            self.return_error( 500, "Error returning data: %s" % str(err) )
            return False

        logger.info( "%d bytes transferred for request %s" % (total_bytes, self.path) )
        return

    def read_request_file(self):
        '''Read a specified request file and return it as a list of tuples.
        
        Fprmat of first 3 lines of file must be:
          quality=<quality>
          minimumlength=<float>
          longestonly=<TRUE|FALSE>
        These values, in this order, will go into `prefix`

        Expected format for the remaining lines is:
          Network Station Location Channel StartTime EndTime

        where the fields are space delimited
        and Network, Station, Location and Channel may contain '*' and '?' wildcards
        and StartTime and EndTime are in YYYY-MM-DDThh:mm:ss.ssssss format or are '*'
        
        Empty locations must be indictaed with --

        Returned tuples have the same fields and ordering as the selection lines.
        '''

        request = []
        linenumber = 1
        linematch = re.compile ('^[\w\?\*]{1,2}\s+[\w\?\*]{1,5}\s+[-\w\?\*]{1,2}\s+[\w\?\*]{1,3}\s+[-:T.*\d]+\s+[-:T.*\d]+$');
        prefix = {'quality':'B','minimumlength':'0.0','longestonly':'FALSE'}
        parts = ['quality','minimumlength','longestonly']
        request_text = self.rfile.read(int(self.headers['Content-Length'])).decode("utf-8")
        logger.info( "POST query:\n%s" % request_text )
        inprefix = True

        for line in request_text.split('\n'):
            line = line.strip()
            
            if line.startswith("#"):
                linenumber = linenumber + 1
                continue
                
            if inprefix:
                prefix_bits = line.split("=")
                if len(prefix_bits)==2:
                    kind = prefix_bits[0].lower()
                    if kind in parts:
                        prefix[kind] = prefix_bits[1]
                        parts.remove(kind)
                        linenumber = linenumber + 1
                        continue

            # Add line to request list if it matches validation regex
            if linematch.match(line):
                fields = line.split()

                # Normalize start and end times to "YYYY-MM-DDThh:mm:ss.ffffff" if not wildcards
                if fields[4] != '*':
                    try:
                        fields[4] = normalize_datetime (fields[4])
                    except:
                        raise ValueError("Cannot normalize start time (line {0:d}): {1:s}".format(linenumber, fields[4]))

                if fields[5] != '*':
                    try:
                        fields[5] = normalize_datetime (fields[5])
                    except:
                        raise ValueError("Cannot normalize start time (line {0:d}): {1:s}".format(linenumber, fields[4]))

                request.append(fields)

            # Raise error if line is not empty and does not start with a #
            elif line and not line.startswith("#"):
                raise ValueError("Unrecognized selection line ({0:d}): '{1:s}'".format(linenumber, line))

            linenumber = linenumber + 1

        
        if len(request) == 0:
            raise ValueError( "No 'N/S/L/C start end' lines present" )
            
        return prefix,request

    def fetch_index_rows(self, prefix, request):
        '''Fetch index rows matching specified request[]

        `request`: List of tuples containing (net,sta,loc,chan,start,end)

        Request elements may contain '?' and '*' wildcards.  The start and
        end elements can be a single '*' if not a date-time string.

        Return rows as list of tuples containing:
        (network,station,location,channel,quality,starttime,endtime,samplerate,
         filename,byteoffset,bytes,hash,timeindex,timespans,timerates,
         format,filemodtime,updated,scanned)
        '''
        index_rows = []
        my_uuid = uuid.uuid4().hex
        request_table = "request_%s" % my_uuid

        try:
            conn = sqlite3.connect(self.server._db_path, 10.0)
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

            for req in request:
                # Replace "--" location ID request alias with true empty value
                if req[2] == "--":
                    req[2] = "";

                cur.execute("INSERT INTO {0} (network,station,location,channel,starttime,endtime) "
                            "VALUES (?,?,?,?,?,?) ".format(request_table), req)

        except Exception as err:
            import traceback
            traceback.print_exc()
            raise ValueError(str(err))

        # Determine if all_channel_summary table exists
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='all_channel_summary'");
        acs_present = cur.fetchone()[0]
    
        wildcards = False
        for req in request:
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
                        "ts.format,ts.filemodtime,ts.updated,ts.scanned "
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
                        .format(self.server._index_table, request_table, "GLOB" if wildcards else "=", self.server._maxsectiondays))
            cur.execute( sql )
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
            cursor.execute( sql )

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
                           "  AND (r.channel='*' OR s.channel GLOB r.channel) ".format(requesttable,requesttable_orig))
            cursor.execute( sql )

        except Exception as err:
            raise ValueError(str(err))

        resolvedrows = cursor.execute("SELECT COUNT(*) FROM {0}".format(requesttable)).fetchone()[0]

        cursor.execute("DROP TABLE {0}".format(requesttable_orig))

        return

def run(options,config):
    '''Run the server w/ the provided options and config
    '''
    logger.info('starting server...')
    db_path = config.get('index_db','path')
    index_table = config.get('server','table') if config.has_option('server','table') else 'tsindex'
  

    class ThreadedServer(ThreadPoolMixIn, HTTPServer):
        def __init__(self, address, handlerClass=testHTTPServer_RequestHandler):
            super().__init__(address, handlerClass)
            self.key = ''

        def set_auth(self, username, password):
            self.key = base64.b64encode(
                bytes('%s:%s' % (username, password), 'utf-8')).decode('ascii')

        def get_auth_key(self):
            return self.key
         
    # Server settings
    server_address = (config.get('server','ip'), int(config.get('server','port')))
    httpd = ThreadedServer(server_address, testHTTPServer_RequestHandler)
    httpd._db_path = db_path
    httpd._index_table = index_table
    if config.has_option('server','username'):
        if config.has_option('server','password'):
            httpd.set_auth(config.get('server','username'), config.get('server','password'))
        else:
            raise("Username specified w/o Password")
    elif config.has_option('server','password'):
        raise("Password specified w/o Username")
    if config.has_option('server','output_cap'):
        try:
            httpd._output_cap = int( config.get('server','output_cap')  )
            if httpd._output_cap <= 0:
                raise("Output Cap must be a positive integer")
        except:
            logger.critical("Invalid output cap (%s); exiting!" % config.get('server','output_cap'))
            sys.exit(1)            
    else:
        httpd._output_cap =  1000000000
    if config.has_option('server','maxsectiondays'):
        try:
            httpd._maxsectiondays = int( config.get('server','maxsectiondays')  )
            if httpd._maxsectiondays <= 0:
                logger.critical("Max Section Days must be positive integer, not %d; exiting!" % config.get('server',_maxsectiondays))
                sys.exit(1)            
        except:
            logger.critical("Invalid Max Section Days (%s); exiting!" % config.get('server','maxsectiondays'))
            sys.exit(1)            
    else:
        httpd._maxsectiondays = 10
        
    msg = 'running dataselect server @ %s:%s' % (config.get('server','ip'), config.get('server','port'))
    logger.info(msg)
    print(msg)
    logger.info('output cap: %d bytes' % httpd._output_cap)
    logger.info('index db: %s' % httpd._db_path)
    logger.info('index table: %s' % httpd._index_table)
    logger.info('maxsectiondays: %s' % httpd._maxsectiondays)
    httpd.serve_forever()
 
def main():
    global logger
    parser = OptionParser(version="%%prog %d.%d.%d"%version)
    parser.add_option("-c", "--configfile", dest="configfile", default = "./server.ini",
                      help="file to read configuration from")
    parser.add_option("-i", "--init",
                      action="store_true", dest="initialize", default=False,
                      help="initialize auxiliary tables in db & quit")

    opts_args = parser.parse_args()
    
    config = configparser.ConfigParser()
    if not os.path.exists(opts_args[0].configfile):
        print("Could not read config file '%s'; exiting!" % opts_args[0].configfile)
        sys.exit(1)
    config.read(opts_args[0].configfile)

    log_path = "./dataselect.log"
    if config.has_option('logging','path'):
        log_path =  config.get('logging','path')
    level_name = 'INFO'
    level_names = ['INFO','DEBUG','WARNING','ERROR','CRITICAL']
    if config.has_option('logging','level'):
        level_name = config.get('logging','level').upper()
        if level_name not in level_names:
            logger.critical("logging:level not a valid logging level; exiting!" % level_name)
            sys.exit(1)
    log_config = {'version':1, 
                'formatters': {
                    'default': {'format': '%(asctime)s - %(levelname)s - %(message)s', 'datefmt': '%Y-%m-%d %H:%M:%S'}
                },
                'handlers': {
                    'file': {
                        'class':'logging.handlers.TimedRotatingFileHandler', 
                        'level':level_name, 
                        'filename':log_path, 
                        'formatter':'default',
                        'when':'d', 
                        'interval':1
                    } },
                'loggers': {
                    'default': { 'level':level_name, 'handlers': ['file'] }
                }
            }
    logging.config.dictConfig( log_config )
    logger = logging.getLogger('default')
    
    req_list = [('index_db','path')]
    if not opts_args[0].initialize:
        req_list.append( ('server','ip') )
        req_list.append( ('server','port') )

    for s,o in req_list:
        if not config.has_option(s,o):
            msg = "%s:%s not provided in '%s'; exiting!" % (s,o,opts_args[0].configfile)
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    
    if not os.path.exists( config.get('index_db','path') ):
        msg = "No file at %s; exiting!" % config.get('index_db','path') 
        logger.critical(msg)
        print(msg)
        sys.exit(1)

    if opts_args[0].initialize:
        logger.info( "Initialization requested" )
        db_path = config.get('index_db','path')
        index_table = config.get('server','table') if config.has_option('server','table') else 'tsindex'
        print("initializing")

        try:
            conn = sqlite3.connect( db_path, 10.0 )
        except Exception as err:
            logger.error( "Could not connect to DB for initialization: %s" % str(err) )
            return
        try:
            c = conn.cursor()
            c.execute( "DROP TABLE all_channel_summary;" )
            c.execute( "CREATE TABLE all_channel_summary AS"
                       "  SELECT network,station,location,channel,"
                       "  min(starttime) AS earliest, max(endtime) AS latest, datetime('now') as updt"
                       "  FROM {0}"
                       "  GROUP BY 1,2,3,4;".format(index_table) )
            conn.commit()
            conn.close()
        except Exception as err:
            logger.error( "Could not run initialization query: %s" % str(err) )
            return
        logger.info("Initialization completed successfully");
        sys.exit(0)

  
    try:
        if int(config.get('server','port')) <= 0:
            raise
    except:
        logger.critical("server:port must be a positive integer; exiting!")
        sys.exit(1)
    
    run(opts_args[0],config)

if __name__ == "__main__":
    main()
