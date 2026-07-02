#!/usr/bin/env python3
"""
TCP Port Scanner
-----------------
A multi-threaded TCP port scanner that checks open/closed/filtered ports
on a single host or a range of hosts.

Features:
- Socket programming (TCP connect scan)
- Concurrency using a thread pool (ThreadPoolExecutor)
- Single host or CIDR / host-range scanning
- Single port, comma list, or port-range scanning
- Results printed to console AND logged to a file
- Graceful handling of timeouts, unreachable hosts, and invalid input

Author: (Your Name)
"""

import socket
import sys
import argparse
import logging
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --------------------------------------------------------------------------
# Logging setup — logs go to both console (via print) and a log file
# --------------------------------------------------------------------------
LOG_FILE = "scan_results.log"

logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def log_and_print(message: str, level: str = "info"):
    """Print to console and simultaneously write to the log file."""
    print(message)
    getattr(logging, level)(message)


# --------------------------------------------------------------------------
# Core scanning logic
# --------------------------------------------------------------------------
def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Attempt a TCP connection to a single (host, port).
    Returns a dict describing the result: open / closed / timeout / error.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = {"host": host, "port": port, "status": None, "service": None}

    try:
        conn_result = sock.connect_ex((host, port))
        if conn_result == 0:
            result["status"] = "open"
            try:
                result["service"] = socket.getservbyport(port, "tcp")
            except OSError:
                result["service"] = "unknown"
        else:
            result["status"] = "closed"
    except socket.timeout:
        result["status"] = "timeout"
    except socket.gaierror:
        result["status"] = "error"
        result["service"] = "hostname could not be resolved"
    except OSError as e:
        result["status"] = "error"
        result["service"] = str(e)
    finally:
        sock.close()

    return result


def parse_ports(port_arg: str) -> list:
    """
    Parse a port argument into a list of integers.
    Supports:
      - single port:      "80"
      - comma list:       "22,80,443"
      - range:             "1-1024"
      - mixed:            "22,80,1000-1010"
    """
    ports = set()
    parts = port_arg.split(",")

    for part in parts:
        part = part.strip()
        if "-" in part:
            try:
                start, end = part.split("-")
                start, end = int(start), int(end)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: '{part}'. Use format like 1-1024."
                )
        else:
            try:
                p = int(part)
                if not (1 <= p <= 65535):
                    raise ValueError
                ports.add(p)
            except ValueError:
                raise argparse.ArgumentTypeError(
                    f"Invalid port: '{part}'. Must be between 1 and 65535."
                )

    return sorted(ports)


def parse_hosts(host_arg: str) -> list:
    """
    Parse a host argument into a list of host strings.
    Supports:
      - single hostname/IP: "example.com" or "192.168.1.10"
      - CIDR notation:      "192.168.1.0/30"
    """
    try:
        network = ipaddress.ip_network(host_arg, strict=False)
        # If it's a /32 single-address "network", ip_network still works.
        return [str(ip) for ip in network.hosts()] or [str(network.network_address)]
    except ValueError:
        # Not a valid IP/CIDR — treat as a plain hostname
        return [host_arg]


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def run_scan(hosts: list, ports: list, timeout: float, max_workers: int):
    open_ports = []
    closed_count = 0
    timeout_count = 0
    error_count = 0

    total_jobs = len(hosts) * len(ports)
    log_and_print(
        f"\n{'='*60}\n"
        f"Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Targets: {len(hosts)} host(s), {len(ports)} port(s), "
        f"{total_jobs} total checks\n"
        f"{'='*60}"
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }

        for future in as_completed(futures):
            host, port = futures[future]
            try:
                result = future.result()
            except Exception as e:
                log_and_print(f"[ERROR] {host}:{port} raised exception: {e}", "error")
                error_count += 1
                continue

            status = result["status"]
            if status == "open":
                open_ports.append(result)
                log_and_print(
                    f"[OPEN]    {result['host']}:{result['port']:<6} "
                    f"({result['service']})"
                )
            elif status == "closed":
                closed_count += 1
            elif status == "timeout":
                timeout_count += 1
            else:  # error
                error_count += 1
                log_and_print(
                    f"[ERROR]   {result['host']}:{result['port']} - {result['service']}",
                    "warning",
                )

    # ---- Summary ----
    log_and_print(
        f"\n{'-'*60}\n"
        f"Scan complete at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"Open: {len(open_ports)} | Closed: {closed_count} | "
        f"Timeouts: {timeout_count} | Errors: {error_count}\n"
        f"{'-'*60}"
    )

    if open_ports:
        log_and_print("\nOpen ports summary:")
        for r in sorted(open_ports, key=lambda x: (x["host"], x["port"])):
            log_and_print(f"  {r['host']:<16} {r['port']:<6} {r['service']}")
    else:
        log_and_print("\nNo open ports found.")

    return open_ports


# --------------------------------------------------------------------------
# CLI entry point
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="A simple multi-threaded TCP port scanner.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py -H 192.168.1.1 -p 80
  python port_scanner.py -H example.com -p 1-1024
  python port_scanner.py -H 192.168.1.0/30 -p 22,80,443 -t 0.5 -w 200
""",
    )
    parser.add_argument(
        "-H", "--host", required=True,
        help="Target host (hostname, IP, or CIDR range e.g. 192.168.1.0/28)"
    )
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Port(s) to scan: single (80), list (22,80,443), "
             "or range (1-1024). Default: 1-1024"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0,
        help="Socket timeout in seconds (default: 1.0)"
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=100,
        help="Max concurrent threads (default: 100)"
    )

    args = parser.parse_args()

    try:
        hosts = parse_hosts(args.host)
    except Exception as e:
        print(f"Error parsing host: {e}")
        sys.exit(1)

    try:
        ports = parse_ports(args.ports)
    except argparse.ArgumentTypeError as e:
        print(f"Error parsing ports: {e}")
        sys.exit(1)

    if not hosts:
        print("No valid hosts to scan.")
        sys.exit(1)

    try:
        run_scan(hosts, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        log_and_print("\nScan interrupted by user.", "warning")
        sys.exit(1)


if __name__ == "__main__":
    main()