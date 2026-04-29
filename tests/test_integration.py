"""
Integration tests for the portable-fdsnws-dataselect HTTP server.

These tests spin up a real HTTP server bound to 127.0.0.1 on an ephemeral
port and make actual HTTP requests against it using the committed test
fixtures in tests/testdata/.

Run all tests:
    pytest

Skip integration tests:
    pytest -m "not integration"
"""

from __future__ import annotations

import http.client
import shutil
import sqlite3
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn

import pytest

from portable_fdsnws_dataselect import version as _pkg_version
from portable_fdsnws_dataselect.handler import HTTPServer_RequestHandler
from portable_fdsnws_dataselect.miniseed import MiniseedDataExtractor

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SRC_DATA = Path(__file__).parent / "testdata"
PREFIX = "/fdsnws/dataselect/1"

# Identifiers matching the fixture data
NET, STA, LOC = "XX", "MS2", "00"

# Time window that falls within the data span
WIN_START = "2010-02-27T07:00:00"
WIN_END   = "2010-02-27T07:10:00"

# End time well past the data end (regression test for silent-hang bug)
PAST_END  = "2010-02-28T00:00:00"


# ---------------------------------------------------------------------------
# Minimal test HTTP server
# ---------------------------------------------------------------------------

class _TestHTTPServer(ThreadingMixIn, HTTPServer):
    """Minimal threaded HTTP server for testing.

    Uses HTTPServer.serve_forever() which supports server.shutdown(),
    unlike ThreadPoolMixIn which uses an unbounded while-True loop.
    """
    daemon_threads = True


def _make_server(db_path: Path, *, has_summary: bool = True) -> _TestHTTPServer:
    """Build a configured _TestHTTPServer bound to 127.0.0.1 on a free port."""
    params: dict = {
        "dbfile": str(db_path),
        "index_table": "tsindex",
        "datapath_replace": False,
        "interface": "127.0.0.1",
        "port": 0,
        "request_limit": 0,
        "maxsectiondays": 10,
        "docroot": "",
        "show_directories": False,
        "shiplogdir": None,
    }
    if has_summary:
        params["summary_table"] = "tsindex_summary"

    server = _TestHTTPServer(("127.0.0.1", 0), HTTPServer_RequestHandler)
    server.params = params
    server.data_extractor = MiniseedDataExtractor(
        params["datapath_replace"], params["request_limit"]
    )
    return server


# ---------------------------------------------------------------------------
# Database fixtures
# ---------------------------------------------------------------------------

def _copy_db_with_local_paths(src: Path, dst: Path) -> None:
    """Copy the SQLite database and rewrite absolute filename paths to point
    at the committed tests/testdata/ directory so tests are portable."""
    shutil.copy(src, dst)
    conn = sqlite3.connect(dst)
    cur = conn.cursor()
    cur.execute("SELECT rowid, filename FROM tsindex")
    for rowid, fn in cur.fetchall():
        new_fn = str(SRC_DATA / Path(fn).name)
        cur.execute("UPDATE tsindex SET filename=? WHERE rowid=?", (new_fn, rowid))
    conn.commit()
    conn.close()


@pytest.fixture
def index_db(tmp_path: Path) -> Path:
    """Portable copy of timeseries.sqlite with filenames rewritten."""
    dst = tmp_path / "timeseries.sqlite"
    _copy_db_with_local_paths(SRC_DATA / "timeseries.sqlite", dst)
    return dst


@pytest.fixture
def index_db_no_summary(tmp_path: Path) -> Path:
    """Like index_db but without the tsindex_summary table, to exercise the
    wildcard-date code path in fetch_index_rows."""
    dst = tmp_path / "timeseries_nosummary.sqlite"
    _copy_db_with_local_paths(SRC_DATA / "timeseries.sqlite", dst)
    conn = sqlite3.connect(dst)
    conn.execute("DROP TABLE IF EXISTS tsindex_summary")
    conn.commit()
    conn.close()
    return dst


# ---------------------------------------------------------------------------
# Server fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def live_server(index_db: Path):
    """Running server with a summary table; yields the base URL."""
    server = _make_server(index_db, has_summary=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


@pytest.fixture
def live_server_no_summary(index_db_no_summary: Path):
    """Running server without a summary table; yields the base URL."""
    server = _make_server(index_db_no_summary, has_summary=False)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _get(url: str) -> urllib.response.addinfourl:
    return urllib.request.urlopen(url, timeout=10)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_version(live_server):
    resp = _get(f"{live_server}{PREFIX}/version")
    assert resp.getcode() == 200
    body = resp.read().decode().strip()
    # /version returns the FDSN service version string "1.1.MMNNPP"
    expected = f"1.1.{_pkg_version[0]:02}{_pkg_version[1]:02}{_pkg_version[2]:02}"
    assert body == expected


@pytest.mark.integration
def test_wadl(live_server):
    resp = _get(f"{live_server}{PREFIX}/application.wadl")
    assert resp.getcode() == 200
    assert "xml" in resp.headers.get("Content-Type", "").lower()
    body = resp.read().decode()
    assert "dataselect" in body.lower()


@pytest.mark.integration
def test_query_returns_mseed_data(live_server):
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        f"&start={WIN_START}&end={WIN_END}"
    )
    resp = _get(url)
    assert resp.getcode() == 200
    assert resp.headers.get("Content-Type") == "application/vnd.fdsn.mseed"
    body = resp.read()
    assert len(body) > 0


@pytest.mark.integration
def test_query_endtime_past_block(live_server):
    """Regression: a request whose end time extends past the indexed range
    must return a complete HTTP response, not hang the connection."""
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        f"&start={WIN_START}&end={PAST_END}"
    )
    resp = _get(url)
    assert resp.getcode() == 200
    assert len(resp.read()) > 0


@pytest.mark.integration
def test_query_nodata_returns_204(live_server):
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=XYZ"
        f"&start={WIN_START}&end={WIN_END}"
    )
    resp = _get(url)
    assert resp.getcode() == 204


@pytest.mark.integration
def test_query_nodata_404(live_server):
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=XYZ"
        f"&start={WIN_START}&end={WIN_END}&nodata=404"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _get(url)
    assert exc_info.value.code == 404


@pytest.mark.integration
def test_query_wildcards_no_summary(live_server_no_summary):
    """Regression: * time wildcards with no summary table must use valid SQLite
    date literals (was '0000-00-00' which returns NULL from datetime())."""
    url = (
        f"{live_server_no_summary}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        "&start=*&end=*"
    )
    resp = _get(url)
    assert resp.getcode() == 200
    assert len(resp.read()) > 0


@pytest.mark.integration
def test_summary_returns_all_channels(live_server):
    url = f"{live_server}{PREFIX}/summary?net={NET}&sta={STA}"
    resp = _get(url)
    assert resp.getcode() == 200
    body = resp.read().decode()
    for channel in ("LH1", "LH2", "LHZ"):
        assert channel in body, f"Expected {channel!r} in summary response"


@pytest.mark.integration
def test_post_query_returns_mseed_data(live_server):
    body_bytes = (
        f"{NET} {STA} {LOC} LHZ {WIN_START} {WIN_END}\n"
    ).encode()
    req = urllib.request.Request(
        f"{live_server}{PREFIX}/query",
        data=body_bytes,
        method="POST",
        headers={
            "Content-Type": "text/plain",
            "Content-Length": str(len(body_bytes)),
        },
    )
    resp = urllib.request.urlopen(req, timeout=10)
    assert resp.getcode() == 200
    assert resp.headers.get("Content-Type") == "application/vnd.fdsn.mseed"
    assert len(resp.read()) > 0


@pytest.mark.integration
def test_redirect_from_root(live_server):
    """Requests outside the service prefix must redirect to the service root."""
    port = int(live_server.rsplit(":", 1)[-1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", "/")
        resp = conn.getresponse()
        assert resp.status == 301
        assert resp.getheader("Location") == f"{PREFIX}/"
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Path-traversal / static-file serving
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_static_path_traversal_rejected(live_server):
    """Encoded ``..`` segments in the static path must not escape docroot."""
    port = int(live_server.rsplit(":", 1)[-1])
    # Use a raw connection so urllib doesn't normalize the URL for us.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        for path in (
            f"{PREFIX}/../../../../etc/passwd",
            f"{PREFIX}/%2E%2E/%2E%2E/%2E%2E/etc/passwd",
            f"{PREFIX}/foo/../../../etc/passwd",
        ):
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
            assert resp.status == 404, (
                f"Path {path!r} returned {resp.status}; body={body[:200]!r}"
            )
    finally:
        conn.close()


@pytest.mark.integration
def test_static_absolute_path_rejected(live_server):
    """Absolute path components must not be honored as filesystem paths."""
    port = int(live_server.rsplit(":", 1)[-1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("GET", f"{PREFIX}//etc/passwd")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 404
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# POST Content-Length handling
# ---------------------------------------------------------------------------

def _raw_request(port: int, raw: bytes) -> tuple[int, bytes]:
    """Send a raw HTTP request and return ``(status_code, body)``.

    Uses a low-level socket so we can construct malformed headers (e.g.
    omit Content-Length on a POST) that http.client refuses to send.
    """
    import socket as _socket

    sock = _socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(raw)
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    response = b"".join(chunks)
    head, _, body = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    status = int(status_line.split(b" ")[1])
    return status, body


@pytest.mark.integration
def test_post_missing_content_length_returns_411(live_server):
    port = int(live_server.rsplit(":", 1)[-1])
    raw = (
        f"POST {PREFIX}/query HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    status, _ = _raw_request(port, raw)
    assert status == 411


@pytest.mark.integration
def test_post_invalid_content_length_returns_400(live_server):
    port = int(live_server.rsplit(":", 1)[-1])
    raw = (
        f"POST {PREFIX}/query HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: not-a-number\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    status, _ = _raw_request(port, raw)
    assert status == 400


@pytest.mark.integration
def test_post_oversized_content_length_returns_413(live_server):
    port = int(live_server.rsplit(":", 1)[-1])
    # 100 GiB; well over the 10 MiB cap
    raw = (
        f"POST {PREFIX}/query HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Length: 107374182400\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    status, body = _raw_request(port, raw)
    assert status == 413, body[:200]


# ---------------------------------------------------------------------------
# Quality filter
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_quality_b_returns_data(live_server):
    """quality=B (best, the default) must not be silently dropped."""
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        f"&start={WIN_START}&end={WIN_END}&quality=B"
    )
    resp = _get(url)
    assert resp.getcode() == 200
    assert len(resp.read()) > 0


@pytest.mark.integration
def test_quality_m_returns_data(live_server):
    """quality=M (merged) is treated as 'any quality'; data must be returned."""
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        f"&start={WIN_START}&end={WIN_END}&quality=M"
    )
    resp = _get(url)
    assert resp.getcode() == 200
    assert len(resp.read()) > 0


@pytest.mark.integration
def test_quality_invalid_returns_400(live_server):
    url = (
        f"{live_server}{PREFIX}/query"
        f"?net={NET}&sta={STA}&loc={LOC}&cha=LHZ"
        f"&start={WIN_START}&end={WIN_END}&quality=Z"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        _get(url)
    assert exc_info.value.code == 400


# ---------------------------------------------------------------------------
# HEAD method
# ---------------------------------------------------------------------------

@pytest.mark.integration
@pytest.mark.parametrize("endpoint", ["query", "summary", "version", "application.wadl"])
def test_head_on_query_endpoints_returns_405(live_server, endpoint):
    """HEAD against any service endpoint must return 405 with Allow: GET, POST,
    not a misleading 200."""
    port = int(live_server.rsplit(":", 1)[-1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("HEAD", f"{PREFIX}/{endpoint}")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 405
        assert resp.getheader("Allow") == "GET, POST"
    finally:
        conn.close()


@pytest.mark.integration
def test_head_on_static_file_returns_200(live_server):
    """HEAD against the bundled documentation must report the real status."""
    port = int(live_server.rsplit(":", 1)[-1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("HEAD", f"{PREFIX}/")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 200
    finally:
        conn.close()


@pytest.mark.integration
def test_head_on_missing_static_returns_404(live_server):
    """HEAD against a non-existent static path must report 404, not 200."""
    port = int(live_server.rsplit(":", 1)[-1])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request("HEAD", f"{PREFIX}/this-file-does-not-exist.html")
        resp = conn.getresponse()
        resp.read()
        assert resp.status == 404
    finally:
        conn.close()
