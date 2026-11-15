#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""A mirror of release files on the loopback, for scripts/install/test.sh.

  python3 -I scripts/install/mirror.py DIR PORTFILE LOG [RATE]

It serves the files under DIR on 127.0.0.1, on a free port that it writes
to PORTFILE. It is also an HTTP proxy: a request with an absolute URL gets
the file of the path of that URL. Each request writes one line to LOG:
"get PATH", "proxy auth=yes|no PATH", "missing PATH" or "cut PATH" (the
client went away before the end). RATE (bytes each second) makes each
file slow, so that a test can stop a download in the middle.
"""

import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(sys.argv[1]).resolve()
LOG = Path(sys.argv[3])
RATE = int(sys.argv[4]) if len(sys.argv) > 4 else 0


def log(line: str) -> None:
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = self.path
        if path.startswith("http://"):
            auth = "yes" if self.headers.get("Proxy-Authorization") else "no"
            path = urlsplit(path).path
            log(f"proxy auth={auth} {path}")
        file = (ROOT / path.lstrip("/")).resolve()
        if ROOT not in file.parents or not file.is_file():
            log(f"missing {path}")
            self.send_error(404)
            return
        data = file.read_bytes()
        log(f"get {path}")
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        step = 16384
        try:
            for i in range(0, len(data), step):
                self.wfile.write(data[i : i + step])
                if RATE:
                    self.wfile.flush()
                    time.sleep(step / RATE)
        except (BrokenPipeError, ConnectionResetError):
            log(f"cut {path}")

    def log_message(self, *args) -> None:
        pass


def main() -> int:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    Path(sys.argv[2]).write_text(str(server.server_address[1]), encoding="utf-8")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
