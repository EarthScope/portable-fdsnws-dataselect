"""
Server startup, configuration parsing, and thread pool.
"""

from __future__ import annotations

import argparse
import base64
import logging.config
import os
import socket
import sqlite3
import sys
import threading
from http.server import HTTPServer
from logging import getLogger
from platform import python_version
from queue import Queue
from configparser import ConfigParser
from shutil import copyfile
from socketserver import ThreadingMixIn

from portable_fdsnws_dataselect import pkg_path, version, __version__
from portable_fdsnws_dataselect.handler import HTTPServer_RequestHandler
from portable_fdsnws_dataselect.miniseed import MiniseedDataExtractor

logger = getLogger(__name__)


class ThreadPoolMixIn(ThreadingMixIn):
    """Use a fixed-size thread pool instead of a new thread per request."""

    numThreads: int = 10
    allow_reuse_address: bool = True  # fix socket reuse on restart

    def serve_forever(self) -> None:
        self.requests: Queue = Queue(self.numThreads)

        for _ in range(self.numThreads):
            t = threading.Thread(target=self.process_request_thread)
            t.daemon = True
            t.start()

        while True:
            self.handle_request()

        self.server_close()

    def process_request_thread(self) -> None:
        while True:
            ThreadingMixIn.process_request_thread(self, *self.requests.get())

    def handle_request(self) -> None:
        try:
            request, client_address = self.get_request()
        except OSError:
            return
        if self.verify_request(request, client_address):
            self.requests.put((request, client_address))


def _config_exit(msg: str) -> None:
    """Log *msg* as critical, print it, and exit with status 1."""
    logger.critical(msg)
    print(msg)
    sys.exit(1)


def _get_int(
    config: ConfigParser,
    section: str,
    key: str,
    default: int,
    *,
    min_val: int | None = None,
    max_exclusive: bool = False,
) -> int:
    """Read an integer option from *config*, exiting on invalid input."""
    if not config.has_option(section, key):
        return default
    raw = config.get(section, key)
    try:
        val = int(raw)
    except ValueError:
        _config_exit(f"Config {section}:{key} ({raw}) is not an integer")
    if min_val is not None:
        if max_exclusive and val <= min_val - 1:
            _config_exit(f"Config {section}:{key} must be > {min_val - 1}, not {val}")
        elif not max_exclusive and val < min_val:
            _config_exit(f"Config {section}:{key} must be >= {min_val}, not {val}")
    return val


def run_server(params: dict) -> None:
    """Start the HTTP server with *params*."""
    logger.info("starting server...")

    class ThreadedServer(ThreadPoolMixIn, HTTPServer):
        def __init__(
            self,
            address: tuple,
            handler_class: type = HTTPServer_RequestHandler,
        ) -> None:
            host = address[0]
            if host:
                try:
                    socket.inet_pton(socket.AF_INET6, host)
                    self.address_family = socket.AF_INET6
                except OSError:
                    self.address_family = socket.AF_INET
            else:
                # No host specified — use IPv6 dual-stack to accept both IPv4 and IPv6
                self.address_family = socket.AF_INET6
            super().__init__(address, handler_class)
            self.key: str = ""

        def server_bind(self) -> None:
            if self.address_family == socket.AF_INET6:
                try:
                    # Disable IPV6_V6ONLY so IPv4 connections are also accepted
                    self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                except (AttributeError, OSError):
                    pass
            super().server_bind()

        def set_auth(self, username: str, password: str) -> None:
            self.key = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode("ascii")

        def get_auth_key(self) -> str:
            return self.key

    server = ThreadedServer((params["interface"], params["port"]), HTTPServer_RequestHandler)
    server.params = params

    if params.get("username") and params.get("password"):
        server.set_auth(params["username"], params["password"])

    msg = f"Started dataselect server ({__version__}) @ http://{server.server_name}:{server.server_port}"
    logger.warning(msg)
    print(msg)

    msg = f"Running under Python {python_version()}"
    logger.warning(msg)

    for p in sorted(server.params):
        logger.info(f"CONFIG {p}: {server.params[p]}")

    server.data_extractor = MiniseedDataExtractor(
        params["datapath_replace"], params["request_limit"]
    )

    server.serve_forever()


class ConfigError(Exception):
    """Raised when the server configuration is invalid."""


def verify_configuration(params: dict) -> None:
    """
    Verify the server configuration.

    Checks that the database file exists and contains a recognized index table
    (and optionally a recognized summary table).

    :raises ConfigError: On any configuration problem.
    """
    if not os.path.isfile(params["dbfile"]):
        raise ConfigError(f"Cannot find database file '{params['dbfile']}'")

    try:
        conn = sqlite3.connect(params["dbfile"], 10.0)
    except Exception as err:
        raise ConfigError(f"Cannot open database: {err}") from err

    try:
        cur = conn.cursor()

        cur.execute(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
            (params["index_table"],),
        )
        if not cur.fetchone()[0]:
            raise ConfigError(f"Cannot find index table '{params['index_table']}' in database")

        cur.execute(f"PRAGMA table_info('{params['index_table']}')")
        index_schema: dict[str, str] = {row[1].lower(): row[2].lower() for row in cur.fetchall()}

        index_version10: dict[str, str] = {
            "network": "text", "station": "text", "location": "text",
            "channel": "text", "quality": "text",
            "starttime": "text", "endtime": "text",
            "samplerate": "real", "filename": "text",
            "byteoffset": "integer", "bytes": "integer",
            "hash": "text", "timeindex": "text",
            "timespans": "text", "timerates": "text",
            "format": "text", "filemodtime": "text",
            "updated": "text", "scanned": "text",
        }
        index_version11 = {**index_version10, "version": "integer"}

        if index_schema != index_version10 and index_schema != index_version11:
            raise ConfigError(
                f"Schema for index table {params['index_table']} is not recognized"
            )

        if "summary_table" in params:
            cur.execute(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
                (params["summary_table"],),
            )
            if not cur.fetchone()[0]:
                raise ConfigError(
                    f"Cannot find summary table '{params['summary_table']}' in database"
                )

            cur.execute(f"PRAGMA table_info('{params['summary_table']}')")
            summary_schema: dict[str, str] = {
                row[1].lower(): (row[2].lower() if row[2] != "" else "text")
                for row in cur.fetchall()
            }

            summary_version10: dict[str, str] = {
                "network": "text", "station": "text",
                "location": "text", "channel": "text",
                "earliest": "text", "latest": "text",
                "updt": "text",
            }

            if summary_schema != summary_version10:
                raise ConfigError(
                    f"Schema for summary table {params['index_table']} is not recognized"
                )
        else:
            logger.warning("No summary table configured.  Such a table is strongly recommended.")
    finally:
        conn.close()


def main() -> None:
    """Parse arguments, read config, configure logging, and start the server."""
    parser = argparse.ArgumentParser(description="Portable fdsnws-dataselect server")
    parser.add_argument("configfile", nargs="?", action="store")
    parser.add_argument(
        "-V", "--version",
        action="store_true", dest="version", default=False,
        help="Print server and Python version and quit",
    )
    parser.add_argument(
        "-s", "--sample_config",
        action="store_true", dest="genconfig", default=False,
        help="Generate a sample config file and quit",
    )
    parser.add_argument(
        "-i", "--init",
        action="store_true", dest="initialize", default=False,
        help="Initialize auxiliary tables in database and quit",
    )
    parser.add_argument(
        "-cd", "--copy_docs",
        action="store", dest="docpath",
        help="Copy documentation web pages to the given directory and quit",
    )

    args = parser.parse_args()

    if args.version:
        print(f"portable-fdsnws-dataselect {__version__}")
        print(f"Running under Python {python_version()}")
        sys.exit(0)

    if args.genconfig:
        with open(os.path.join(os.path.dirname(pkg_path), "example", "server.ini")) as f:
            print(f.read())
        sys.exit(0)

    if args.docpath:
        if not os.path.exists(args.docpath):
            print(f"Can't copy documentation to nonexistent path '{args.docpath}'")
            sys.exit(1)
        srcpath = os.path.join(os.path.dirname(pkg_path), "docs")
        for filename in os.listdir(srcpath):
            _, ext = os.path.splitext(filename)
            if ext in (".html", ".css"):
                dst = copyfile(
                    os.path.join(srcpath, filename),
                    os.path.join(args.docpath, filename),
                )
                print(f"Created '{dst}'")
        sys.exit(0)

    if not args.configfile:
        parser.error("No database file is specified.  Try -h for more help.")

    if not os.path.exists(args.configfile):
        print(f"Configuration file '{args.configfile}' does not exist")
        sys.exit(1)

    config = ConfigParser()
    config.read(args.configfile)

    config_dir = os.path.dirname(os.path.abspath(args.configfile))

    def _resolve_path(p: str) -> str:
        """Resolve *p* relative to the config file's directory if not absolute."""
        return p if os.path.isabs(p) else os.path.join(config_dir, p)

    # -- logging ---------------------------------------------------------------

    if config.has_option("logging", "path"):
        log_path = _resolve_path(config.get("logging", "path"))
        level_names = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        level_name = config.get("logging", "level", fallback="INFO").upper()
        if level_name not in level_names:
            _config_exit(f"logging level '{level_name}' not valid, exiting!")

        logging.config.dictConfig({
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": "%(asctime)s - %(levelname)s - %(message)s",
                    "datefmt": "%Y-%m-%d %H:%M:%S",
                },
            },
            "handlers": {
                "file": {
                    "class": "logging.handlers.TimedRotatingFileHandler",
                    "level": level_name,
                    "filename": log_path,
                    "formatter": "default",
                    "when": "d",
                    "interval": 1,
                },
            },
            "loggers": {
                "": {"handlers": ["file"], "level": level_name, "propagate": True},
            },
        })
    else:
        logging.getLogger().setLevel(99)

    # -- configuration parsing -------------------------------------------------

    params: dict = {}

    if config.has_option("index_db", "path"):
        params["dbfile"] = _resolve_path(config.get("index_db", "path"))
    else:
        _config_exit("Required database file (index_db:path) is not specified")

    params["index_table"] = config.get("index_db", "table", fallback="tsindex")

    if config.has_option("index_db", "summary_table"):
        params["summary_table"] = config.get("index_db", "summary_table")

    if config.has_option("index_db", "datapath_replace"):
        raw = config.get("index_db", "datapath_replace")
        parts = raw.split(",")
        if len(parts) != 2:
            _config_exit(
                f"datapath substitution must be two strings separated by a comma, not '{raw}', exiting!"
            )
        params["datapath_replace"] = (parts[0].strip(' "'), parts[1].strip(' "'))
    else:
        params["datapath_replace"] = False

    params["interface"] = config.get("server", "interface", fallback="")
    params["port"] = _get_int(config, "server", "port", 80, min_val=1, max_exclusive=True)
    params["request_limit"] = _get_int(config, "server", "request_limit", 0, min_val=0)
    params["username"] = config.get("server", "username", fallback=None)
    params["password"] = config.get("server", "password", fallback=None)

    if bool(params["username"]) != bool(params["password"]):
        _config_exit("Username and password must be specified together, exiting")

    params["maxsectiondays"] = _get_int(config, "server", "maxsectiondays", 10, min_val=1, max_exclusive=True)
    raw_docroot = config.get("server", "docroot", fallback="")
    params["docroot"] = _resolve_path(raw_docroot) if raw_docroot else ""

    if config.has_option("server", "show_directories"):
        try:
            params["show_directories"] = config.getboolean("server", "show_directories")
        except ValueError:
            params["show_directories"] = False
    else:
        params["show_directories"] = False

    if config.has_option("logging", "shiplogdir"):
        params["shiplogdir"] = _resolve_path(config.get("logging", "shiplogdir"))
        if not os.path.isdir(params["shiplogdir"]):
            _config_exit(
                f"Cannot find shipment logging directory at '{params['shiplogdir']}', exiting!"
            )
    else:
        params["shiplogdir"] = None

    # -- initialization --------------------------------------------------------

    if args.initialize:
        if "summary_table" in params:
            logger.info(f"Initializing summary table {params['summary_table']}")
            print(f"Initializing summary table {params['summary_table']}")
            try:
                conn = sqlite3.connect(params["dbfile"], 10.0)
            except Exception as err:
                logger.error(f"Could not connect to DB for initialization: {err}")
                return
            try:
                c = conn.cursor()
                c.execute(f"DROP TABLE IF EXISTS {params['summary_table']};")
                c.execute(
                    f"CREATE TABLE {params['summary_table']} AS"
                    "  SELECT network,station,location,channel,"
                    "  min(starttime) AS earliest, max(endtime) AS latest, datetime('now') as updt"
                    f"  FROM {params['index_table']}"
                    "  GROUP BY 1,2,3,4;"
                )
                conn.commit()
            except Exception as err:
                logger.error(f"Could not run initialization query: {err}")
                return
            finally:
                conn.close()
            logger.info("Initialization completed successfully")
            sys.exit(0)
        else:
            print("Cannot initialize, summary table is not defined in the configuration")
            sys.exit(1)

    # -- verify config then start server ---------------------------------------

    try:
        verify_configuration(params)
    except ConfigError as err:
        msg = str(err)
        print(msg)
        print("Configuration error, exiting.")
        logger.critical(msg)
        logger.critical("Configuration error, exiting.")
        sys.exit(1)
    except Exception:
        logger.exception("Unexpected error verifying configuration")

    try:
        run_server(params)
    except (KeyboardInterrupt, SystemExit):
        logger.info("shutting down")
        print("\nshutting down")
    except Exception:
        logger.exception("Unexpected server error")


if __name__ == "__main__":
    main()
