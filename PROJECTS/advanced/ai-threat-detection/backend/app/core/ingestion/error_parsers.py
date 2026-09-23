"""
©AngelaMos | 2026
error_parsers.py

Nginx error-log parser (Challenge 5: Request Body Analysis
via Error Logs)

Nginx error logs are far less structured than access logs.
A typical line looks like:

  2026/03/15 09:22:31 [error] 7#7: *1234 upstream sent
  invalid header while reading response header from
  upstream, client: 93.184.216.34, server: _, request:
  "POST /api/login HTTP/1.1", host: "example.com"

ParsedErrorEntry captures timestamp, level, pid/tid, an
optional connection id, the free-form message, and any
client/server/request/host fields nginx appended to the
message. parse_error_line extracts these via a primary
regex for the fixed-format prefix plus secondary regexes
for the loosely-structured suffix fields

Connects to:
  core/ingestion/
    error_tailer    - DualLogTailer feeds raw error lines
  core/features/
    body_features   - entropy/attack-pattern analysis of
                       the message text
  core/enrichment/
    correlator      - correlates ParsedErrorEntry with
                       ParsedLogEntry by ip + timestamp
"""

import re
from dataclasses import dataclass
from datetime import datetime, UTC


@dataclass(frozen=True, slots=True)
class ParsedErrorEntry:
    """
    Structured representation of a single nginx error log line.
    """

    timestamp: datetime
    level: str
    pid: int
    tid: int
    connection_id: int | None
    message: str
    client_ip: str | None
    server: str | None
    request_method: str | None
    request_path: str | None
    host: str | None
    raw_line: str


_TIMESTAMP_FMT = "%Y/%m/%d %H:%M:%S"

_ERROR_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) "
    r"\[(?P<level>\w+)\] "
    r"(?P<pid>\d+)#(?P<tid>\d+): "
    r"(?:\*(?P<connid>\d+)\s+)?"
    r"(?P<message>.*)$"
)

_CLIENT_RE = re.compile(r"client:\s*([^,]+)")
_SERVER_RE = re.compile(r"server:\s*([^,]+)")
_HOST_RE = re.compile(r'host:\s*"([^"]*)"')
_REQUEST_RE = re.compile(r'request:\s*"([A-Z]+)\s+(\S+)\s+HTTP/[\d.]+"')


def parse_error_line(line: str) -> ParsedErrorEntry | None:
    """
    Parse a single nginx error log line into a ParsedErrorEntry.

    Returns None for lines that don't match the fixed-format
    nginx error log prefix.
    """
    if not line:
        return None

    match = _ERROR_RE.match(line)
    if not match:
        return None

    try:
        timestamp = datetime.strptime(match["timestamp"], _TIMESTAMP_FMT).replace(tzinfo=UTC)
    except ValueError:
        return None

    message = match["message"]
    connid_raw = match["connid"]

    client_match = _CLIENT_RE.search(message)
    server_match = _SERVER_RE.search(message)
    host_match = _HOST_RE.search(message)
    request_match = _REQUEST_RE.search(message)

    return ParsedErrorEntry(
        timestamp=timestamp,
        level=match["level"],
        pid=int(match["pid"]),
        tid=int(match["tid"]),
        connection_id=int(connid_raw) if connid_raw else None,
        message=message,
        client_ip=client_match.group(1).strip() if client_match else None,
        server=server_match.group(1).strip() if server_match else None,
        request_method=request_match.group(1) if request_match else None,
        request_path=request_match.group(2) if request_match else None,
        host=host_match.group(1) if host_match else None,
        raw_line=line,
    )