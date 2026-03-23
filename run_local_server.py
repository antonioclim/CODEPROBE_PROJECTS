#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import socket
import webbrowser
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def main() -> None:
    root = Path(__file__).resolve().parent
    os.chdir(root)
    port = find_free_port()
    url = f"http://127.0.0.1:{port}/index.html"
    print(f"Serving CodeProbe from: {root}")
    print(f"Open: {url}")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    server = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
