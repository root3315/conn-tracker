# conn-tracker

Real-time network connection monitor for Linux. Reads directly from `/proc/net` to show active TCP/UDP connections with process info.

## Why I built this

Needed something lightweight to see what's connecting where without pulling in heavy dependencies. `netstat` is deprecated, `ss` is fine but I wanted something I could tweak. This reads straight from procfs.

## Quick start

```bash
# Run with root for full process info
sudo python3 conn_tracker.py

# Or just run it (some process names might show as unknown)
python3 conn_tracker.py
```

## Usage

```
python3 conn_tracker.py [options]

Options:
  -i, --interval SEC   Refresh interval (default: 2 seconds)
  -f, --filter PROTO   Filter by protocol: tcp, udp, or all
  -s, --state STATE    Filter by state: ESTABLISHED, LISTEN, TIME_WAIT, etc.
  -n, --no-clear       Don't clear screen between updates
  --once               Show connections once and exit
  -t, --timeout        Show connection duration and timeout info
```

## Examples

```bash
# Watch only established TCP connections
sudo python3 conn_tracker.py -f tcp -s ESTABLISHED

# Quick snapshot, no refresh
python3 conn_tracker.py --once

# Faster refresh rate
sudo python3 conn_tracker.py -i 0.5

# Keep scrollback history (no screen clear)
python3 conn_tracker.py -n

# Show connection duration and kernel timer info
sudo python3 conn_tracker.py -t
```

## Output

```
conn-tracker [2026-03-10 14:23:45]
------------------------------------------------------------
PROTO LOCAL ADDRESS              REMOTE ADDRESS             STATE        PID/PROCESS
============================================================
tcp   192.168.1.10:443           10.0.0.5:52341             ESTABLISHED  1234/nginx
tcp   0.0.0.0:22                 0.0.0.0:0                  LISTEN       892/sshd
udp   0.0.0.0:53                 0.0.0.0:0                  LISTEN       445/dnsmasq
------------------------------------------------------------
Total: 3 connections | ESTABLISHED: 1, LISTEN: 2
```

### With timeout info (`-t` flag)

```
conn-tracker [2026-03-10 14:23:45]
------------------------------------------------------------
PROTO LOCAL ADDRESS              REMOTE ADDRESS             STATE        DURATION  TIMER    PID/PROCESS
============================================================
tcp   192.168.1.10:443           10.0.0.5:52341             ESTABLISHED      45s     0.0s   1234/nginx
tcp   0.0.0.0:22                 0.0.0.0:0                  LISTEN          2m 0.0s   892/sshd
------------------------------------------------------------
Total: 2 connections | ESTABLISHED: 1, LISTEN: 1
```

## How it works

- Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6`
- Parses hex-encoded addresses and ports
- Walks `/proc/[pid]/fd` to match socket inodes to processes
- Tracks connection duration and state changes over time
- Reads kernel timer values for retransmit/timeout info
- No external dependencies, pure stdlib

## Requirements

- Linux (uses procfs)
- Python 3.6+
- Root/sudo for full process info (otherwise some PIDs show as unknown)

## Notes

- IPv4 and IPv6 both supported
- UDP "connections" are really just bound sockets (UDP is stateless)
- Process lookup can be slow on systems with many processes
- Duration tracking starts when conn-tracker begins monitoring
