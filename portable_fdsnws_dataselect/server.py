from socketserver import ThreadingMixIn
from queue import Queue
import threading
import sqlite3
import logging.config
import argparse
from http.server import HTTPServer
import os.path

from portable_fdsnws_dataselect import pkg_path, version
from portable_fdsnws_dataselect.handler import HTTPServer_RequestHandler
import socket
import base64
import sys
import configparser
from portable_fdsnws_dataselect.miniseed import MiniseedDataExtractor

logger = None


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

        for _ in range(self.numThreads):
            t = threading.Thread(target=self.process_request_thread)
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


def run_server(params):
    '''Run the server w/ the provided options and config
    '''
    logger.info('starting server...')

    class ThreadedServer(ThreadPoolMixIn, HTTPServer):
        def __init__(self, address, handlerClass=HTTPServer_RequestHandler):
            super().__init__(address, handlerClass)
            self.key = ''

        def set_auth(self, username, password):
            self.key = base64.b64encode(
                bytes('%s:%s' % (username, password), 'utf-8')).decode('ascii')

        def get_auth_key(self):
            return self.key

    server = ThreadedServer((params['interface'], params['port']), HTTPServer_RequestHandler)
    server.params = params

    if 'username' in params and 'password' in params:
        server.set_auth(params['username'], params['password'])

    msg = 'running dataselect server @ %s:%d' % (params['interface'], params['port'])
    logger.info(msg)
    print(msg)

    for p in sorted(server.params.keys()):
        logger.info('CONFIG %s: %s' % (p, str(server.params[p])))

    # Create and configure the data extraction
    server.data_extractor = MiniseedDataExtractor(
        params['datapath_replace'], params['request_limit'])

    server.serve_forever()


def main():
    '''
    Read/validate options; read config file; set up logging
    Run the server
    '''
    global logger

    # Build argument parser
    parser = argparse.ArgumentParser(description='Portable fdsnws-dataselect server')
    parser.add_argument('configfile', action='store')
    parser.add_argument("-s", "--sample_config",
                        action="store_true", dest="genconfig", default=False,
                        help="Generate a sample config file & quit")
    parser.add_argument("-i", "--init",
                        action="store_true", dest="initialize", default=False,
                        help="Initialize auxiliary tables in database and quit")

    args = parser.parse_args()

    # Return sample configuration file
    if args.genconfig:
        with open(os.path.join(os.path.dirname(pkg_path), 'example', 'server.ini'), 'r') as f:
            print(f.read())
        sys.exit(0)

    # Check for and read config file
    if not os.path.exists(args.configfile):
        print("Configuration file '%s' does not exist" % args.configfile)
        sys.exit(1)

    config = configparser.ConfigParser()
    config.read(args.configfile)

    # Set up logging
    if config.has_option('logging', 'path'):
        log_path = config.get('logging', 'path')

        level_name = 'INFO'
        level_names = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

        if config.has_option('logging', 'level'):
            level_name = config.get('logging', 'level').upper()

        if level_name not in level_names:
            logger.critical("logging level '%s' not valid, exiting!" % level_name)
            sys.exit(1)

        log_config = {
            'version': 1,
            'formatters': {
                'default': {'format': '%(asctime)s - %(levelname)s - %(message)s',
                            'datefmt': '%Y-%m-%d %H:%M:%S'},
            },
            'handlers': {
                'file': {
                    'class': 'logging.handlers.TimedRotatingFileHandler',
                    'level': level_name,
                    'filename': log_path,
                    'formatter': 'default',
                    'when': 'd',
                    'interval': 1
                }
            },
            'loggers': {
                'default': {'level': level_name, 'handlers': ['file']}
            }
        }
        logging.config.dictConfig(log_config)

    else:
        # If no log file defined set log level for no output
        logging.getLogger().setLevel(99)

    logger = logging.getLogger('default')

    # Validate, set defaults and map config file options to params
    params = dict()

    # Database file, required
    if config.has_option('index_db', 'path'):
        params['dbfile'] = config.get('index_db', 'path')

        if not os.path.isfile(params['dbfile']):
            msg = "Cannot find database file at '%s', exiting!" % params['dbfile']
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    else:
        msg = "Required database file (index_db:path) is not specified"
        logger.critical(msg)
        print(msg)
        sys.exit(1)

    # Database table
    if config.has_option('index_db', 'table'):
        params['index_table'] = config.get('index_db', 'table')
    else:
        params['index_table'] = 'tsindex'

    # Data file path substitution
    if config.has_option('index_db', 'datapath_replace'):
        subop = config.get('index_db', 'datapath_replace').split(",")

        if len(subop) != 2:
            msg = "datapath substition must be two strings separated by a comma not '%s', exiting!" % config.get('index_db', 'datapath_replace')
            logger.critical(msg)
            print(msg)
            sys.exit(1)

        # Store replacement while stripping surrounding spaces and double quote
        params['datapath_replace'] = (subop[0].strip(' "'), subop[1].strip(' "'))

    else:
        params['datapath_replace'] = False

    # Server interface/address
    if config.has_option('server', 'interface'):
        params['interface'] = config.get('server', 'interface')
    else:
        params['interface'] = ''

    # Server port
    if config.has_option('server', 'port'):
        try:
            params['port'] = int(config.get('server', 'port'))

            if params['port'] <= 0:
                msg = "Config server:port must be a positive integer, not %d" % params['port']
                logger.critical(msg)
                print(msg)
                sys.exit(1)

        except ValueError:
            msg = "Config server:port (%s) is not an integer" % config.get('server', 'port')
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    else:
        params['port'] = 80

    # Request limit in bytes
    if config.has_option('server', 'request_limit'):
        try:
            params['request_limit'] = int(config.get('server', 'request_limit'))

            if params['request_limit'] < 0:
                msg = "Config server:request_limit must be >= 0, not %d" % params['request_limit']
                logger.critical(msg)
                print(msg)
                sys.exit(1)

        except ValueError:
            msg = "Config server:request_limit (%s) is not an integer" % config.get('server', 'request_limit')
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    else:
        params['request_limit'] = 0

    # User name and password
    if config.has_option('server', 'username'):
        params['username'] = config.get('server', 'username')
    else:
        params['username'] = None
    if config.has_option('server', 'password'):
        params['password'] = config.get('server', 'password')
    else:
        params['password'] = None

    if (params['username'] and not params['password']) or (params['password'] and not params['username']):
        msg = "Username and password must be specified together, exiting"
        logger.critical(msg)
        print(msg)
        sys.exit(1)

    # Max section days
    if config.has_option('server', 'maxsectiondays'):
        try:
            params['maxsectiondays'] = int(config.get('server', 'maxsectiondays'))

            if params['maxsectiondays'] <= 0:
                msg = "Config server:maxsectiondays must be > 0, not %d" % params['maxsectiondays']
                logger.critical(msg)
                print(msg)
                sys.exit(1)

        except ValueError:
            msg = "Config server:maxsectiondays (%s) is not an integer" % config.get('server', 'maxsectiondays')
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    else:
        params['maxsectiondays'] = 10

    # Shipment logging directory
    if config.has_option('logging', 'shiplogdir'):
        params['shiplogdir'] = config.get('logging', 'shiplogdir')

        if not os.path.isdir(params['shiplogdir']):
            msg = "Cannot find shipment logging directory at '%s', exiting!" % params['shiplogdir']
            logger.critical(msg)
            print(msg)
            sys.exit(1)
    else:
        params['shiplogdir'] = None

    # Perform initialization of all_channel_summary table in DB if requested
    if args.initialize:
        logger.info("Initialization requested")
        print("initializing")

        try:
            conn = sqlite3.connect(params['dbfile'], 10.0)
        except Exception as err:
            logger.error("Could not connect to DB for initialization: %s" % str(err))
            return

        try:
            c = conn.cursor()
            c.execute("DROP TABLE IF EXISTS all_channel_summary;")
            c.execute("CREATE TABLE all_channel_summary AS"
                      "  SELECT network,station,location,channel,"
                      "  min(starttime) AS earliest, max(endtime) AS latest, datetime('now') as updt"
                      "  FROM {0}"
                      "  GROUP BY 1,2,3,4;".format(params['index_table']))
            conn.commit()
            conn.close()
        except Exception as err:
            logger.error("Could not run initialization query: %s" % str(err))
            return

        logger.info("Initialization completed successfully")
        sys.exit(0)

    # Start the server!
    try:
        run_server(params)

    except (KeyboardInterrupt, SystemExit):
        logger.info("shutting down")
        print("\nshutting down")

    except Exception:
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
