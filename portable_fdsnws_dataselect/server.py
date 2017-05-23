from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
from future.builtins import *  # NOQA

import threading
import sqlite3
import logging.config
import argparse
import os
import socket
import base64
import sys

from logging import getLogger
from http.server import HTTPServer
from socketserver import ThreadingMixIn
from queue import Queue
from platform import python_version
from configparser import ConfigParser
from shutil import copyfile
from portable_fdsnws_dataselect import pkg_path, version
from portable_fdsnws_dataselect.handler import HTTPServer_RequestHandler
from portable_fdsnws_dataselect.miniseed import MiniseedDataExtractor

logger = getLogger(__name__)


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

    # Note that `object` is the base class here, we need this to make super() work in Python 2
    # See http://stackoverflow.com/a/18392639/1005790
    class ThreadedServer(ThreadPoolMixIn, HTTPServer, object):
        def __init__(self, address, handlerClass=HTTPServer_RequestHandler):
            super(ThreadedServer, self).__init__(address, handlerClass)
            self.key = ''

        def set_auth(self, username, password):
            self.key = base64.b64encode(
                ('%s:%s' % (username, password)).encode('utf-8')).decode('ascii')

        def get_auth_key(self):
            return self.key

    server = ThreadedServer((params['interface'], params['port']), HTTPServer_RequestHandler)
    server.params = params

    if 'username' in params and 'password' in params:
        server.set_auth(params['username'], params['password'])

    msg = ('Started dataselect server (%s) @ http://%s:%d'
           % (".".join(str(i) for i in version),
              server.server_name,
              server.server_port))
    logger.warning(msg)
    print(msg)

    msg = 'Running under Python %s' % python_version()
    logger.warning(msg)

    for p in sorted(server.params.keys()):
        logger.info('CONFIG %s: %s' % (p, str(server.params[p])))

    # Create and configure the data extraction
    server.data_extractor = MiniseedDataExtractor(
        params['datapath_replace'], params['request_limit'])

    server.serve_forever()


class ConfigError(Exception):
    def __init__(self, message):
        self.message = message


def verify_configuration(params, level=0):
    '''Verify the server's configuration.

    Open the database, check for index table, check for summary table.
    '''

    # Database file exists
    if not os.path.isfile(params['dbfile']):
        raise ConfigError("Cannot find database file '%s'" % params['dbfile'])

    # Database can be opened
    try:
        conn = sqlite3.connect(params['dbfile'], 10.0)
    except Exception as err:
        raise ConfigError("Cannot open database: " + str(err))

    cur = conn.cursor()

    # Specified index table exists
    cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='%s'" % params['index_table'])
    if not cur.fetchone()[0]:
        raise ConfigError("Cannot find index table '%s' in database" % params['index_table'])

    # Fetch index table definition and construct a dictionary for comparison
    cur.execute("PRAGMA table_info('%s')" % params['index_table'])
    index_schema = dict()
    for row in cur.fetchall():
        index_schema[row[1].lower()] = row[2].lower()

    # Definition of time series index schema version 1.0
    index_version10 = {'network': 'text', 'station': 'text', 'location': 'text',
                       'channel': 'text', 'quality': 'text',
                       'starttime': 'text', 'endtime': 'text',
                       'samplerate': 'real', 'filename': 'text',
                       'byteoffset': 'integer', 'bytes': 'integer',
                       'hash': 'text', 'timeindex': 'text',
                       'timespans': 'text', 'timerates': 'text',
                       'format': 'text', 'filemodtime': 'text',
                       'updated': 'text', 'scanned': 'text'}

    # Index table schema is version 1.0
    if index_schema != index_version10:
        raise ConfigError("Schema for index table %s is not recognized" % params['index_table'])

    if 'summary_table' in params:
        # The summary table exists
        cur.execute("SELECT count(*) FROM sqlite_master WHERE type='table' and name='%s'" % params['summary_table'])
        if not cur.fetchone()[0]:
            raise ConfigError("Cannot find summary table '%s' in database" % params['summary_table'])

        # Fetch summary table definition and construct a dictionary for comparison
        cur.execute("PRAGMA table_info('%s')" % params['summary_table'])
        summary_schema = dict()
        for row in cur.fetchall():
            summary_schema[row[1].lower()] = row[2].lower() if row[2] != '' else 'text'

        # Definition of summary schema version 1.0
        summary_version10 = {'network': 'text', 'station': 'text',
                             'location': 'text', 'channel': 'text',
                             'earliest': 'text', 'latest': 'text',
                             'updt': 'text'}

        # Summary table schema is version 1.0
        if summary_schema != summary_version10:
            raise ConfigError("Schema for summary table %s is not recognized" % params['index_table'])
    else:
        logger.warning("No summary table configured.  Such a table is strongly recommended.")

    conn.close()

    return


def main():
    '''
    Read/validate options; read config file; set up logging
    Run the server
    '''
    global logger

    # Build argument parser
    parser = argparse.ArgumentParser(description='Portable fdsnws-dataselect server')
    parser.add_argument('configfile', nargs='?', action='store')
    parser.add_argument("-V", "--version",
                        action="store_true", dest="version", default=False,
                        help="Print server and Python version and quit")
    parser.add_argument("-s", "--sample_config",
                        action="store_true", dest="genconfig", default=False,
                        help="Generate a sample config file and quit")
    parser.add_argument("-i", "--init",
                        action="store_true", dest="initialize", default=False,
                        help="Initialize auxiliary tables in database and quit")
    parser.add_argument("-cd", "--copy_docs",
                        action="store", dest="docpath",
                        help="Copy documentation web pages to the given directory and quit")

    args = parser.parse_args()

    # Print versions
    if args.version:
        print('portable-fdsnws-dataselect %s' % ".".join(str(i) for i in version))
        print('Running under Python %s' % python_version())
        sys.exit(0)

    # Print sample configuration file
    if args.genconfig:
        with open(os.path.join(os.path.dirname(pkg_path), 'example', 'server.ini'), 'r') as f:
            print(f.read())
        sys.exit(0)

    # Copy documentation
    if args.docpath:
        if not os.path.exists(args.docpath):
            print("Can't copy documentation to nonexistent path '%s'" % args.docpath)
            sys.exit(1)
        srcpath = os.path.join(os.path.dirname(pkg_path), 'docs')
        filenames = os.listdir(srcpath)
        for filename in filenames:
            (_root, ext) = os.path.splitext(filename)
            if ext in ('.html', '.css',):
                dst = copyfile(os.path.join(srcpath, filename), os.path.join(args.docpath, filename))
                print("Created '%s'" % dst)
        sys.exit(0)

    if not args.configfile:
        parser.error('No database file is specified.  Try -h for more help.')

    # Check for and read config file
    if not os.path.exists(args.configfile):
        print("Configuration file '%s' does not exist" % args.configfile)
        sys.exit(1)

    config = ConfigParser()
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
            'disable_existing_loggers': False,
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
                '': {'handlers': ['file'],
                     'level': level_name,
                     'propagate': True,
                }
            }
        }
        logging.config.dictConfig(log_config)

    else:
        # If no log file defined set log level for no output
        logging.getLogger().setLevel(99)

    # Validate, set defaults and map config file options to params
    params = dict()

    # Database file, required
    if config.has_option('index_db', 'path'):
        params['dbfile'] = config.get('index_db', 'path')

    else:
        msg = "Required database file (index_db:path) is not specified"
        logger.critical(msg)
        print(msg)
        sys.exit(1)

    # Index table
    if config.has_option('index_db', 'table'):
        params['index_table'] = config.get('index_db', 'table')
    else:
        params['index_table'] = 'tsindex'

    # Summary table
    if config.has_option('index_db', 'summary_table'):
        params['summary_table'] = config.get('index_db', 'summary_table')

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

    # Static document root
    if config.has_option('server', 'docroot'):
        params['docroot'] = config.get('server', 'docroot')
    else:
        params['docroot'] = ''

    # Show directory listings?
    if config.has_option('server', 'show_directories'):
        try:
            params['show_directories'] = config.getboolean('server', 'show_directories')
        except ValueError:
            params['show_directories'] = False
    else:
        params['show_directories'] = False

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

    # Perform initialization of summary table in DB if requested
    if args.initialize:
        if 'summary_table' in params:
            logger.info("Initializing summary table %s" % params['summary_table'])
            print("Initializing summary table %s" % params['summary_table'])

            try:
                conn = sqlite3.connect(params['dbfile'], 10.0)
            except Exception as err:
                logger.error("Could not connect to DB for initialization: %s" % str(err))
                return

            try:
                c = conn.cursor()
                c.execute("DROP TABLE IF EXISTS %s;" % params['summary_table'])
                c.execute("CREATE TABLE {0} AS"
                          "  SELECT network,station,location,channel,"
                          "  min(starttime) AS earliest, max(endtime) AS latest, datetime('now') as updt"
                          "  FROM {1}"
                          "  GROUP BY 1,2,3,4;".format(params['summary_table'], params['index_table']))
                conn.commit()
            except Exception as err:
                logger.error("Could not run initialization query: %s" % str(err))
                return

            conn.close()
            logger.info("Initialization completed successfully")
            sys.exit(0)
        else:
            print("Cannot initialize, summary table is not defined in the configuration")
            sys.exit(1)

    # Verify configuration details
    try:
        verify_configuration(params, level=0)
    except ConfigError as err:
        print(err.message)
        print("Configuration error, exiting.")
        logger.critical(err.message)
        logger.critical("Configuration error, exiting.")
        sys.exit(1)
    except Exception:
        import traceback
        traceback.print_exc()

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
