"""
HTTP request handler.
"""

import contextlib
import datetime
import os.path
import sqlite3
import socket
import time
import uuid
from http.server import SimpleHTTPRequestHandler
from logging import getLogger, DEBUG
from typing import Iterator, NamedTuple, Optional
from urllib.parse import urlparse

from pymseed import NSTMODULUS, nstime2timestr

from portable_fdsnws_dataselect import pkg_path, version, __version__
from portable_fdsnws_dataselect.miniseed import NoDataError, RequestLimitExceededError
from portable_fdsnws_dataselect.request import DataselectRequest, NonQueryURLError, QueryError

logger = getLogger(__name__)

# Mapping of HTTP status codes to short descriptions
HTTP_MSGS: dict[int, str] = {
    200: "Successful request, results follow",
    204: "Request was properly formatted and submitted but no data matches the selection",
    400: "Bad request",
    401: "Unauthorized, authentication required",
    403: "Authentication failed or access blocked to restricted data",
    404: "Request was properly formatted and submitted but no data matches the selection",
    413: "Request would result in too much data being returned or the request itself is too large",
    414: "Request URI too large",
    500: "Internal server error",
    503: "Service temporarily unavailable",
}


class IndexRow(NamedTuple):
    """One row returned by the time-series index query."""

    network: str
    station: str
    location: str
    channel: str
    quality: str
    starttime: str
    endtime: str
    samplerate: float
    filename: str
    byteoffset: int
    bytes: int
    hash: Optional[str]
    timeindex: Optional[str]
    timespans: Optional[str]
    timerates: Optional[str]
    format: Optional[str]
    filemodtime: Optional[str]
    updated: Optional[str]
    scanned: Optional[str]
    requeststart: str
    requestend: str


class SummaryRow(NamedTuple):
    """One row returned by the summary query."""

    network: str
    station: str
    location: str
    channel: str
    earliest: str
    latest: str
    updated: str


@contextlib.contextmanager
def _db_request_table(
    dbfile: str,
    query_rows: list[list[str]],
    columns: str,
    insert_cols: str,
    placeholders: str,
    row_slice: slice = slice(None),
) -> Iterator[tuple[sqlite3.Cursor, str, str]]:
    """
    Context manager that opens *dbfile*, creates a temporary request table,
    inserts *query_rows*, and yields ``(cursor, request_table, summary_table)``.

    The connection is always closed on exit regardless of exceptions.

    The `--` location code used in FDSN requests is normalised to `""` (empty)
    before insertion, matching the index database convention.
    """
    try:
        conn = sqlite3.connect(dbfile, 10.0)
    except Exception as err:
        raise ValueError(str(err)) from err

    request_table = f"request_{uuid.uuid4().hex}"
    try:
        cur = conn.cursor()
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute(f"CREATE TEMPORARY TABLE {request_table} ({columns})")

        for req in query_rows:
            row = list(req[row_slice])
            if len(row) > 2 and row[2] == "--":
                row[2] = ""
            cur.execute(
                f"INSERT INTO {request_table} ({insert_cols}) VALUES ({placeholders})",
                row,
            )

        # Determine summary table name from the cursor's connection
        # (server params are not accessible here; resolved by caller convention)
        summary_table = _resolve_summary_table(cur)

        yield cur, request_table, summary_table

        cur.execute(f"DROP TABLE IF EXISTS {request_table}")
    except ValueError:
        raise
    except Exception as err:
        logger.exception("Database error")
        raise ValueError(str(err)) from err
    finally:
        conn.close()


def _resolve_summary_table(cur: sqlite3.Cursor) -> str:
    """Return an empty string sentinel; callers resolve the name themselves."""
    return ""


class HTTPServer_RequestHandler(SimpleHTTPRequestHandler):

    prefix = f"/fdsnws/dataselect/1/"

    # -- simple response helpers -----------------------------------------------

    def do_HEAD(self) -> None:
        """Send response code and header for a normal successful response."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self) -> None:
        """Send response code and header requesting HTTP Basic authentication."""
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'basic realm="FDSNWS"')
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def return_error(self, code: int, err_msg: str) -> None:
        """Log *err_msg* and write an FDSN-style plain-text error response."""
        msg = (
            f"Error {code}: {HTTP_MSGS[code]}\n\n"
            f"{err_msg}\n\n"
            f"Usage details are available from {self.prefix}\n\n"
            f"Request:\n{self.format_host()}\n\n"
            f"Request Submitted:\n{datetime.datetime.now().isoformat()}\n\n"
            f"Service version:\n"
            f"Service: fdsnws-dataselect  version {__version__}\n"
        )
        self.send_response(code)
        self.send_header("Content-type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(msg.encode())
        logger.error(f"Code:{code} Error:{err_msg} Request:{self.path}")

    def return_version(self) -> None:
        """Return the service version string."""
        service_version = f"1.1.{version[0]:02}{version[1]:02}{version[2]:02}"
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(f"{service_version}\n".encode())

    def return_wadl(self) -> None:
        """Return the application.wadl document."""
        self.send_response(200)
        self.send_header("Content-type", "application/xml")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        port_suffix = "" if self.server.server_port == 80 else f":{self.server.server_port}"
        base_url = f"http://{self.server.server_name}{port_suffix}{self.prefix}"
        wadl_path = os.path.join(os.path.dirname(pkg_path), "docs", "application.wadl")
        with open(wadl_path) as f:
            self.wfile.write((f.read() % base_url).encode())

    def format_host(self, query: str = "") -> str:
        """Return the full URL for this host with an optional query string."""
        path = urlparse(self.path).path
        return f"http://{self.server.server_name}:{self.server.server_port}{path}{query}"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        logger.info(f"{self.address_string()} {format % args}")

    # -- request dispatch ------------------------------------------------------

    def do_GET(self) -> None:
        """Handle a GET request."""
        logger.debug(f"GET: {self.path}")
        try:
            request = DataselectRequest(self.path)
            self.common_process(request)
        except QueryError as e:
            self.return_error(400, str(e))
        except NonQueryURLError:
            self.handle_nonquery()

    def do_POST(self) -> None:
        """Handle a POST request."""
        logger.debug(f"POST: {self.path}")
        request_text = self.rfile.read(int(self.headers["Content-Length"])).decode()
        logger.debug(f"POST query:\n{request_text}")
        try:
            request = DataselectRequest(self.path, request_text)
            self.common_process(request)
        except QueryError as e:
            self.return_error(400, str(e))
        except NonQueryURLError:
            self.return_error(404, "File not found")

    def common_process(self, request: DataselectRequest) -> None:
        """Shared processing path for GET and POST requests."""
        if request.endpoint == "version":
            self.return_version()
            return
        elif request.endpoint == "application.wadl":
            self.return_wadl()
            return
        elif request.endpoint == "summary":
            summary_rows = self.fetch_summary_rows(request.query_rows)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            header = (
                f"#{'Net':<7s}{'Sta':<8s}{'Loc':<8s}{'Chan':<8s}"
                f"{'Earliest':<32s}{'Latest':<32s}{'Updated':<32s}\n"
            )
            self.wfile.write(header.encode())
            for row in summary_rows:
                loc = row.location if row.location != "" else "--"
                line = (
                    f"{row.network:<8s}{row.station:<8s}{loc:<8s}{row.channel:<8s}"
                    f"{row.earliest:<32s}{row.latest:<32s}{row.updated:<32s}\n"
                )
                self.wfile.write(line.encode())
            return
        elif request.endpoint == "queryauth":
            self.return_error(403, "Authorization via the 'queryauth' endpoint not implemented")
            return

        request_time = time.time()
        request_time_str = nstime2timestr(int(request_time) * NSTMODULUS)

        if logger.isEnabledFor(DEBUG):
            for key, val in request.bulk_params.items():
                logger.debug(f"REQUEST: {key} = {val}")
            for row in request.query_rows:
                logger.debug(f"REQUEST: {' '.join(row)}")

        try:
            index_rows = self.fetch_index_rows(request.query_rows, request.bulk_params)
        except Exception as err:
            self.return_error(400, str(err))
            return

        total_bytes = 0
        src_bytes: dict[str, int] = {}

        logger.debug("Starting data return")

        try:
            for data_segment in self.server.data_extractor.extract_data(index_rows):
                shipped_bytes = data_segment.num_bytes
                src_name = data_segment.src_name
                if shipped_bytes > 0:
                    if total_bytes == 0:
                        self.send_response(200)
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.send_header("Content-Type", "application/vnd.fdsn.mseed")
                        self.send_header(
                            "Content-Disposition",
                            f"attachment; filename=fdsnws-dataselect_{request_time_str}.mseed",
                        )
                        self.end_headers()
                    data_segment.write(self.wfile)
                    total_bytes += shipped_bytes
                    src_bytes[src_name] = src_bytes.get(src_name, 0) + shipped_bytes
        except NoDataError:
            self.return_error(int(request.bulk_params["nodata"]), "No data matched selection")
            return
        except RequestLimitExceededError as limit_err:
            self.return_error(413, str(limit_err))
            return
        except Exception as err:
            self.return_error(500, str(err))
            return

        duration = time.time() - request_time

        if self.server.params["shiplogdir"]:
            client_ip = self.address_string()
            try:
                client_host = socket.gethostbyaddr(client_ip)[0]
            except Exception:
                client_host = client_ip
            user_agent = self.headers.get("User-Agent", "?")
            shiplogfile = os.path.join(
                self.server.params["shiplogdir"],
                time.strftime("shipment-%Y-%m-%dZ", time.gmtime(request_time)),
            )
            logger.debug(f"Writing shipment log to {shiplogfile}")
            with open(shiplogfile, "a") as f:
                f.write(
                    f"START CLIENT {client_host} [{client_ip}] @ {request_time_str} [{user_agent}]\n"
                )
                for srcname in sorted(src_bytes):
                    f.write(f"{srcname} {src_bytes[srcname]}\n")
                f.write(f"END CLIENT {client_host} [{client_ip}] total bytes: {total_bytes}\n")

        logger.info(f"shipped {total_bytes} bytes for request {self.path} in {duration:.0f} seconds")

    # -- database helpers ------------------------------------------------------

    def _summary_table_name(self) -> str:
        """Return the configured summary table name."""
        return self.server.params.get(
            "summary_table",
            f"{self.server.params['index_table']}_summary",
        )

    def fetch_index_rows(
        self, query_rows: list[list[str]], bulk_params: dict[str, str]
    ) -> list[IndexRow]:
        """
        Query the time-series index for rows matching *query_rows*.

        Returns a sorted list of :class:`IndexRow` named tuples.
        """
        dbfile = self.server.params["dbfile"]
        summary_table = self._summary_table_name()
        index_table = self.server.params["index_table"]
        days = self.server.params["maxsectiondays"]
        request_table = f"request_{uuid.uuid4().hex}"
        logger.debug(f"Opening SQLite database for index rows: {dbfile}")

        try:
            conn = sqlite3.connect(dbfile, 10.0)
        except Exception as err:
            raise ValueError(str(err)) from err

        try:
            cur = conn.cursor()
            cur.execute("PRAGMA temp_store=MEMORY")

            cur.execute(
                f"CREATE TEMPORARY TABLE {request_table} "
                "(network TEXT, station TEXT, location TEXT, channel TEXT, "
                "starttime TEXT, endtime TEXT)"
            )
            for req in query_rows:
                row = list(req)
                if row[2] == "--":
                    row[2] = ""
                cur.execute(
                    f"INSERT INTO {request_table} "
                    "(network,station,location,channel,starttime,endtime) "
                    "VALUES (?,?,?,?,?,?)",
                    row,
                )

            cur.execute(
                "SELECT count(*) FROM sqlite_master "
                f"WHERE type='table' AND name='{summary_table}'"
            )
            summary_present = cur.fetchone()[0]

            wildcards = any(
                "*" in field or "?" in field for req in query_rows for field in req
            )

            if wildcards:
                if summary_present:
                    self.resolve_request(cur, summary_table, request_table)
                    wildcards = False
                else:
                    cur.execute(
                        f"UPDATE {request_table} SET starttime='0000-00-00T00:00:00' "
                        "WHERE starttime='*'"
                    )
                    cur.execute(
                        f"UPDATE {request_table} SET endtime='5000-00-00T00:00:00' "
                        "WHERE endtime='*'"
                    )

            op = "GLOB" if wildcards else "="

            sql = (
                "SELECT DISTINCT ts.network,ts.station,ts.location,ts.channel,ts.quality, "
                "ts.starttime,ts.endtime,ts.samplerate, "
                "ts.filename,ts.byteoffset,ts.bytes,ts.hash, "
                "ts.timeindex,ts.timespans,ts.timerates, "
                "ts.format,ts.filemodtime,ts.updated,ts.scanned, r.starttime, r.endtime "
                f"FROM {index_table} ts, {request_table} r "
                "WHERE "
                f"  ts.network {op} r.network "
                f"  AND ts.station {op} r.station "
                f"  AND ts.location {op} r.location "
                f"  AND ts.channel {op} r.channel "
                "  AND ts.starttime <= r.endtime "
                f"  AND ts.starttime >= datetime(r.starttime,'-{days} days') "
                "  AND ts.endtime >= r.starttime"
            )

            if bulk_params.get("quality") in ("D", "R", "Q"):
                sql += f" AND quality = '{bulk_params['quality']}'"

            try:
                cur.execute(sql)
            except Exception as err:
                logger.exception("Error executing index query")
                raise ValueError(str(err)) from err

            index_rows = [IndexRow(*row) for row in cur.fetchall()]
            index_rows.sort()
            logger.debug(f"Fetched {len(index_rows)} index rows")

            cur.execute(f"DROP TABLE {request_table}")
        except ValueError:
            raise
        except Exception as err:
            logger.exception("Error fetching index rows")
            raise ValueError(str(err)) from err
        finally:
            conn.close()

        return index_rows

    def resolve_request(
        self, cursor, summary_table: str, request_table: str
    ) -> int:
        """
        Resolve wildcard entries in *request_table* using *summary_table*.

        Renames the original table, rebuilds it via a JOIN, then drops the
        original. Returns the number of resolved rows.
        """
        orig_table = f"{request_table}_orig"
        try:
            cursor.execute(f"ALTER TABLE {request_table} RENAME TO {orig_table}")
            cursor.execute(
                f"CREATE TEMPORARY TABLE {request_table} "
                "(network TEXT, station TEXT, location TEXT, channel TEXT, "
                "starttime TEXT, endtime TEXT)"
            )
            cursor.execute(
                f"INSERT INTO {request_table} (network,station,location,channel,starttime,endtime) "
                f"SELECT s.network,s.station,s.location,s.channel,"
                "CASE WHEN r.starttime='*' THEN s.earliest ELSE r.starttime END,"
                "CASE WHEN r.endtime='*' THEN s.latest ELSE r.endtime END "
                f"FROM {summary_table} s, {orig_table} r "
                "WHERE "
                "  (r.starttime='*' OR r.starttime <= s.latest) "
                "  AND (r.endtime='*' OR r.endtime >= s.earliest) "
                "  AND (r.network='*' OR s.network GLOB r.network) "
                "  AND (r.station='*' OR s.station GLOB r.station) "
                "  AND (r.location='*' OR s.location GLOB r.location) "
                "  AND (r.channel='*' OR s.channel GLOB r.channel)"
            )
        except Exception as err:
            raise ValueError(str(err)) from err

        resolved = cursor.execute(f"SELECT COUNT(*) FROM {request_table}").fetchone()[0]
        logger.debug(f"Resolved request with summary into {resolved} rows")
        cursor.execute(f"DROP TABLE {orig_table}")
        return resolved

    def fetch_summary_rows(self, query_rows: list[list[str]]) -> list[SummaryRow]:
        """
        Query the summary table for rows matching *query_rows*.

        Returns a sorted list of :class:`SummaryRow` named tuples (empty list
        when no summary table exists).
        """
        dbfile = self.server.params["dbfile"]
        summary_table = self._summary_table_name()
        request_table = f"request_{uuid.uuid4().hex}"
        logger.debug(f"Opening SQLite database for summary rows: {dbfile}")

        try:
            conn = sqlite3.connect(dbfile, 10.0)
        except Exception as err:
            raise ValueError(str(err)) from err

        summary_rows: list[SummaryRow] = []
        try:
            cur = conn.cursor()
            cur.execute("PRAGMA temp_store=MEMORY")

            cur.execute(
                f"CREATE TEMPORARY TABLE {request_table} "
                "(network TEXT, station TEXT, location TEXT, channel TEXT)"
            )
            for req in query_rows:
                row = list(req[:4])
                if row[2] == "--":
                    row[2] = ""
                cur.execute(
                    f"INSERT INTO {request_table} (network,station,location,channel) "
                    "VALUES (?,?,?,?)",
                    row,
                )

            cur.execute(
                "SELECT count(*) FROM sqlite_master "
                f"WHERE type='table' AND name='{summary_table}'"
            )
            summary_present = cur.fetchone()[0]

            if summary_present:
                try:
                    cur.execute(
                        "SELECT DISTINCT s.network,s.station,s.location,s.channel,"
                        "s.earliest,s.latest,s.updt "
                        f"FROM {summary_table} s, {request_table} r "
                        "WHERE "
                        "  (r.network='*' OR s.network GLOB r.network) "
                        "  AND (r.station='*' OR s.station GLOB r.station) "
                        "  AND (r.location='*' OR s.location GLOB r.location) "
                        "  AND (r.channel='*' OR s.channel GLOB r.channel)"
                    )
                except Exception as err:
                    raise ValueError(str(err)) from err

                summary_rows = [SummaryRow(*row) for row in cur.fetchall()]
                summary_rows.sort()
                logger.debug(f"Fetched {len(summary_rows)} summary rows")

            cur.execute(f"DROP TABLE {request_table}")
        except ValueError:
            raise
        except Exception as err:
            logger.exception("Error fetching summary rows")
            raise ValueError(str(err)) from err
        finally:
            conn.close()

        return summary_rows

    # -- static file serving ---------------------------------------------------

    def handle_nonquery(self) -> None:
        """
        Fall back to static file serving for non-query URLs.

        Requests outside the service prefix are redirected to the prefix.
        """
        request_path = urlparse(self.path).path
        if not request_path.startswith(self.prefix):
            self.send_response(301)
            self.send_header("Location", self.prefix)
            self.end_headers()
        else:
            f = self.send_head()
            if f:
                self.copyfile(f, self.wfile)
                f.close()

    def translate_path(self, path: str) -> str:
        """
        Map a URL path to a filesystem path for static file serving.

        Strips the service prefix and resolves relative to the configured docroot.
        """
        docroot = self.server.params["docroot"] or os.path.join(
            os.path.dirname(pkg_path), "docs"
        )
        relative_parts = self.path[len(self.prefix) :].split("/")
        return os.path.join(docroot, *relative_parts)

    def list_directory(self, path: str):
        """
        Override directory listing to require explicit configuration.

        Returns a 404 unless ``show_directories`` is enabled in the server config.
        """
        if self.server.params["show_directories"]:
            return super().list_directory(path)
        self.send_error(404, "No permission to list directory")
        return None
