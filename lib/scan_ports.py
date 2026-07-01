#!/usr/bin/env python3
"""SpyAI TCP connect port scanner (stdlib only, no nmap)."""

from __future__ import annotations

import argparse
import concurrent.futures
import socket
import sys
from typing import Iterable, List, Sequence, Tuple

DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 50

# Heuristic service labels for the Markdown report (not full version detection).
SERVICE_HINTS: dict[int, Tuple[str, str]] = {
    22: ("ssh", "-"),
    25: ("smtp", "-"),
    53: ("domain", "-"),
    80: ("http", "-"),
    135: ("msrpc", "-"),
    139: ("netbios-ssn", "-"),
    443: ("https", "-"),
    445: ("microsoft-ds", "-"),
    3000: ("http", "dev"),
    3001: ("http", "dev"),
    3306: ("mysql", "-"),
    3389: ("ms-wbt-server", "-"),
    4000: ("http", "-"),
    5000: ("http", "-"),
    5432: ("postgresql", "-"),
    5601: ("http", "kibana"),
    5678: ("http", "n8n"),
    6333: ("http", "qdrant"),
    6334: ("http", "qdrant-grpc"),
    6379: ("redis", "-"),
    8081: ("http-proxy", "-"),
    8443: ("https-alt", "-"),
    8888: ("http-alt", "-"),
    9000: ("http", "-"),
    9001: ("http", "-"),
    9200: ("http", "elasticsearch"),
    11434: ("http", "ollama"),
    27017: ("mongodb", "-"),
}


def parse_ports(spec: str) -> List[int]:
    ports: List[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        p = int(part)
        if p < 1 or p > 65535:
            raise ValueError(f"invalid port: {p}")
        ports.append(p)
    return sorted(set(ports))


def try_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def scan(host: str, ports: Sequence[int], timeout: float, workers: int) -> List[int]:
    if not ports:
        return []
    open_ports: List[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(try_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            if fut.result():
                open_ports.append(port)
    return sorted(open_ports)


def infer_service(port: int) -> Tuple[str, str]:
    if port in SERVICE_HINTS:
        return SERVICE_HINTS[port]
    if 8000 <= port <= 8080:
        return ("http", "ai-likely")
    return ("open", "-")


def write_report(host: str, open_ports: Iterable[int], path: str) -> None:
    lines = [
        "# SpyAI TCP connect scan",
        f"Host: {host} ()",
        "Status: Up",
        "",
        "PORT   STATE SERVICE VERSION",
    ]
    for port in open_ports:
        svc, ver = infer_service(port)
        lines.append(f"{port}/tcp open {svc} {ver}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="SpyAI parallel TCP connect port scan")
    ap.add_argument("host", help="target IP or hostname")
    ap.add_argument("-o", "--output", required=True, help="nmap-style output file for spy-ai")
    ap.add_argument("-p", "--ports", required=True, help="comma-separated port list")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="connect timeout (seconds)")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="parallel workers")
    args = ap.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"scanning {len(ports)} port(s) on {args.host} ...", file=sys.stderr)
    open_ports = scan(args.host, ports, args.timeout, args.workers)
    write_report(args.host, open_ports, args.output)
    print(f"open: {len(open_ports)}", file=sys.stderr)
    if open_ports:
        print(" ".join(str(p) for p in open_ports), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
