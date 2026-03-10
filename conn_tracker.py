#!/usr/bin/env python3
"""
conn-tracker: Real-time network connection monitor
Tracks active TCP/UDP connections and displays them with process info
"""

import os
import sys
import time
import socket
import argparse
from datetime import datetime
from collections import defaultdict

PROC_NET_TCP = "/proc/net/tcp"
PROC_NET_TCP6 = "/proc/net/tcp6"
PROC_NET_UDP = "/proc/net/udp"
PROC_NET_UDP6 = "/proc/net/udp6"

CONNECTION_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

connection_history = {}


def hex_to_ip(hex_ip, ipv6=False):
    """Convert hex IP address to human-readable format."""
    if ipv6:
        hex_ip = hex_ip.zfill(32)
        groups = [hex_ip[i:i+4] for i in range(0, 32, 4)]
        return ":".join(
            str(int(g[2:4], 16)) + str(int(g[0:2], 16)).zfill(2)
            if int(g[2:4], 16) == 0
            else hex(int(g[0:2], 16))[2:] + g[2:4]
            for g in groups
        )
    else:
        try:
            addr = int(hex_ip, 16)
            return ".".join(
                str((addr >> (8 * i)) & 0xFF) for i in range(4)
            )
        except ValueError:
            return "0.0.0.0"


def hex_to_port(hex_port):
    """Convert hex port to integer."""
    try:
        return int(hex_port, 16)
    except ValueError:
        return 0


def hex_to_timer(hex_timer):
    """Convert hex timer value to seconds."""
    try:
        timer_val = int(hex_timer, 16)
        return timer_val / 100.0
    except ValueError:
        return 0.0


def get_process_info(inode):
    """Find process owning a socket by inode."""
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        fd_path = f"/proc/{pid_dir}/fd"
        if not os.path.isdir(fd_path):
            continue
        try:
            for fd in os.listdir(fd_path):
                try:
                    link = os.readlink(f"{fd_path}/{fd}")
                    if f"socket:[{inode}]" in link:
                        cmd_path = f"/proc/{pid_dir}/cmdline"
                        with open(cmd_path, "r") as f:
                            cmdline = f.read().replace("\x00", " ").strip()
                        return pid_dir, cmdline or "unknown"
                except (OSError, IOError):
                    continue
        except (OSError, IOError):
            continue
    return None, None


def parse_net_file(filepath, protocol="tcp", ipv6=False):
    """Parse /proc/net/tcp or similar files."""
    connections = []
    if not os.path.exists(filepath):
        return connections

    try:
        with open(filepath, "r") as f:
            lines = f.readlines()[1:]
    except (IOError, OSError):
        return connections

    for line in lines:
        parts = line.split()
        if len(parts) < 12:
            continue

        local_addr_hex, local_port_hex = parts[1].split(":")
        remote_addr_hex, remote_port_hex = parts[2].split(":")
        state_hex = parts[3]
        inode = parts[9]
        timer_hex = parts[10] if len(parts) > 10 else "0"

        local_ip = hex_to_ip(local_addr_hex, ipv6)
        local_port = hex_to_port(local_port_hex)
        remote_ip = hex_to_ip(remote_addr_hex, ipv6)
        remote_port = hex_to_port(remote_port_hex)
        state = CONNECTION_STATES.get(state_hex, f"UNKNOWN({state_hex})")
        timer_secs = hex_to_timer(timer_hex)

        pid, cmdline = get_process_info(inode)

        conn_key = f"{protocol}:{local_ip}:{local_port}:{remote_ip}:{remote_port}"

        connections.append({
            "protocol": protocol.upper() + ("6" if ipv6 else ""),
            "local_ip": local_ip,
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "state": state,
            "pid": pid,
            "process": cmdline,
            "inode": inode,
            "timer_secs": timer_secs,
            "conn_key": conn_key,
        })

    return connections


def get_all_connections():
    """Gather all network connections from proc filesystem."""
    all_conns = []

    for filepath, protocol, ipv6 in [
        (PROC_NET_TCP, "tcp", False),
        (PROC_NET_TCP6, "tcp", True),
        (PROC_NET_UDP, "udp", False),
        (PROC_NET_UDP6, "udp", True),
    ]:
        all_conns.extend(parse_net_file(filepath, protocol, ipv6))

    return all_conns


def update_connection_history(connections):
    """Update connection history with timestamps and duration tracking."""
    global connection_history
    current_time = time.time()
    seen_keys = set()

    for conn in connections:
        conn_key = conn["conn_key"]
        seen_keys.add(conn_key)

        if conn_key not in connection_history:
            connection_history[conn_key] = {
                "first_seen": current_time,
                "last_state": conn["state"],
                "state_changes": [],
                "duration": 0.0,
            }
        else:
            history = connection_history[conn_key]
            if history["last_state"] != conn["state"]:
                history["state_changes"].append({
                    "from": history["last_state"],
                    "to": conn["state"],
                    "time": current_time,
                })
                history["last_state"] = conn["state"]
            history["duration"] = current_time - history["first_seen"]

        conn["duration"] = connection_history[conn_key]["duration"]
        conn["first_seen"] = connection_history[conn_key]["first_seen"]

    stale_keys = [k for k in connection_history if k not in seen_keys]
    for key in stale_keys:
        del connection_history[key]


def format_duration(secs):
    """Format duration in human-readable format."""
    if secs < 1.0:
        return f"{secs:.1f}s"
    elif secs < 60.0:
        return f"{secs:.0f}s"
    elif secs < 3600.0:
        mins = int(secs // 60)
        remaining_secs = int(secs % 60)
        return f"{mins}m {remaining_secs}s"
    else:
        hours = int(secs // 3600)
        mins = int((secs % 3600) // 60)
        return f"{hours}h {mins}m"


def format_connection(conn, show_timeout=False):
    """Format a single connection for display."""
    local = f"{conn['local_ip']}:{conn['local_port']}"
    remote = f"{conn['remote_ip']}:{conn['remote_port']}"
    proto = conn['protocol'].ljust(5)
    state = conn['state'].ljust(12)
    
    pid_info = f"{conn['pid'] or '-'}"
    if conn['process']:
        proc_name = conn['process'][:30]
        pid_info = f"{pid_info}/{proc_name}"
    else:
        pid_info = pid_info.ljust(15)

    if show_timeout:
        duration = format_duration(conn.get('duration', 0.0))
        timer = f"{conn.get('timer_secs', 0.0):.1f}s"
        return f"{proto} {local:<28} {remote:<28} {state} {duration:>8} {timer:>8} {pid_info}"
    else:
        return f"{proto} {local:<28} {remote:<28} {state} {pid_info}"


def clear_screen():
    """Clear terminal screen."""
    os.system("clear" if os.name == "posix" else "cls")


def print_header(show_timeout=False):
    """Print table header."""
    if show_timeout:
        header = f"{'PROTO':<5} {'LOCAL ADDRESS':<28} {'REMOTE ADDRESS':<28} {'STATE':<12} {'DURATION':>8} {'TIMER':>8} {'PID/PROCESS'}"
    else:
        header = f"{'PROTO':<5} {'LOCAL ADDRESS':<28} {'REMOTE ADDRESS':<28} {'STATE':<12} {'PID/PROCESS'}"
    print("=" * len(header))
    print(header)
    print("=" * len(header))


def count_by_state(connections):
    """Count connections grouped by state."""
    counts = defaultdict(int)
    for conn in connections:
        counts[conn['state']] += 1
    return dict(counts)


def main():
    parser = argparse.ArgumentParser(
        description="Track active network connections in real time"
    )
    parser.add_argument(
        "-i", "--interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds (default: 2)"
    )
    parser.add_argument(
        "-f", "--filter",
        choices=["tcp", "udp", "all"],
        default="all",
        help="Filter by protocol (default: all)"
    )
    parser.add_argument(
        "-s", "--state",
        help="Filter by connection state (e.g., ESTABLISHED, LISTEN)"
    )
    parser.add_argument(
        "-n", "--no-clear",
        action="store_true",
        help="Disable screen clearing between updates"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run once and exit (no continuous monitoring)"
    )
    parser.add_argument(
        "-t", "--timeout",
        action="store_true",
        help="Show connection duration and timeout info"
    )

    args = parser.parse_args()

    if os.geteuid() != 0:
        print("Warning: Running without root privileges. Some process info may be unavailable.")

    try:
        iteration = 0
        while True:
            iteration += 1
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if not args.no_clear and not args.once:
                clear_screen()
            elif iteration > 1 and not args.once:
                print()

            print(f"conn-tracker [{timestamp}]")
            print("-" * 60)

            connections = get_all_connections()

            if args.filter != "all":
                connections = [
                    c for c in connections
                    if c['protocol'].lower().startswith(args.filter)
                ]

            if args.state:
                connections = [
                    c for c in connections
                    if c['state'] == args.state.upper()
                ]

            update_connection_history(connections)

            print_header(show_timeout=args.timeout)

            if not connections:
                print("No active connections found.")
            else:
                for conn in connections:
                    print(format_connection(conn, show_timeout=args.timeout))

            print("-" * 60)
            state_counts = count_by_state(connections)
            summary = ", ".join(f"{k}: {v}" for k, v in sorted(state_counts.items()))
            print(f"Total: {len(connections)} connections | {summary or 'N/A'}")

            if args.once:
                break

            print(f"\nPress Ctrl+C to exit. Refreshing in {args.interval}s...")
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n\nconn-tracker stopped by user.")
        sys.exit(0)
    except PermissionError as e:
        print(f"Permission error: {e}")
        print("Try running with sudo for full process information.")
        sys.exit(1)


if __name__ == "__main__":
    main()
