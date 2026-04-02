# Packet Sniffer

A command-line network packet sniffer built in Python using Scapy. Captures live network traffic, parses packet headers, and displays real-time information about network activity — including source/destination IPs, protocols, ports, TCP flags, and packet sizes.

Built as a hands-on project to understand how tools like Wireshark and tcpdump work under the hood.

---

## Features

- Captures live TCP, UDP, and ICMP packets from your network interface
- Identifies well-known ports by service name (e.g. `443 → HTTPS`, `22 → SSH`)
- Displays TCP flags (`SYN`, `ACK`, `FIN`, `RST`) for each packet
- Filters traffic by protocol, IP address, or port number using BPF syntax
- Saves full capture logs to a text file with a summary report
- Shows top active IP addresses at the end of each session

---

## Project Structure

```
packet-sniffer/
├── sniffer.py        # Entry point — capture loop, CLI argument handling, display
├── parser.py         # Packet parsing — extracts fields from each IP/TCP/UDP/ICMP packet
├── logger.py         # File logging — writes capture data and summary report to disk
├── requirements.txt  # Python dependencies
└── README.md
```

---

## Requirements

- Python 3.7+
- [Scapy](https://scapy.net/) — packet capture and manipulation library
- Root / administrator privileges (required for raw socket access)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/JoshRJHung/packet-sniffer.git
cd packet-sniffer

# 2. Install dependencies
pip install -r requirements.txt
```

---

## Usage

> **Note:** Must be run with `sudo` on Linux/macOS, or as Administrator on Windows.

```bash
# Capture all packets (unlimited)
sudo python3 sniffer.py

# Stop after 100 packets
sudo python3 sniffer.py -c 100

# Filter by protocol
sudo python3 sniffer.py -f tcp
sudo python3 sniffer.py -f udp
sudo python3 sniffer.py -f icmp

# Filter by IP address
sudo python3 sniffer.py -ip 192.168.1.1

# Filter by port
sudo python3 sniffer.py -p 443

# Save output to a log file
sudo python3 sniffer.py -o results.txt

# Combine filters
sudo python3 sniffer.py -f tcp -p 443 -c 50 -o https_capture.txt
```

### Command-line flags

| Flag | Long form | Description |
|------|-----------|-------------|
| `-c` | `--count` | Number of packets to capture (default: unlimited) |
| `-f` | `--filter` | Protocol filter: `tcp`, `udp`, or `icmp` |
| `-ip` | `--ip-address` | Filter by source or destination IP address |
| `-p` | `--port` | Filter by port number |
| `-o` | `--output` | Save output to a text file |

---

## Example Output

```
════════════════════════════════════════════════════════════
  PACKET SNIFFER  —  press Ctrl+C to stop
════════════════════════════════════════════════════════════
  Filter   : tcp and port 443
  Limit    : 10
  Log file : none
════════════════════════════════════════════════════════════
  TIME       #       PROTO  SOURCE               DESTINATION          PORTS                               SIZE
────────────────────────────────────────────────────────────
[14:32:01] #1     TCP    192.168.1.5        → 142.250.80.46      52341 → 443 (HTTPS) [SYN]           74 bytes
[14:32:01] #2     TCP    142.250.80.46      → 192.168.1.5        443 (HTTPS) → 52341 [SYN ACK]       74 bytes
[14:32:01] #3     TCP    192.168.1.5        → 142.250.80.46      52341 → 443 (HTTPS) [ACK]           66 bytes
[14:32:02] #4     TCP    192.168.1.5        → 142.250.80.46      52341 → 443 (HTTPS) [PSH ACK]       130 bytes
```

---

## What I Learned

- **How packets are structured** — network traffic is layered (Ethernet → IP → TCP/UDP → data), and each layer has its own header fields that tools like Wireshark parse and display
- **TCP handshake and flags** — the SYN → SYN/ACK → ACK sequence that establishes every TCP connection, and what RST/FIN mean for connection teardown
- **BPF (Berkeley Packet Filter) syntax** — the filter language used by Wireshark, tcpdump, and most network security tools
- **Promiscuous mode** — how network cards can be set to capture all traffic on a network segment, not just traffic addressed to the local machine
- **Python fundamentals** — argparse for CLI tools, classes for stateful objects, file I/O, dictionaries, and separation of concerns across multiple files
- **Why root privileges are required** — raw socket access sits below the OS's normal permission layer, so capturing packets requires elevated privileges

---

## Possible Extensions

- Add color-coded terminal output using `colorama` (highlight SYN floods, Telnet, etc.)
- Add a `--interface` flag to choose which network card to sniff on
- Detect suspicious patterns (e.g. port scanning — many packets to different ports from one IP)
- Export to `.pcap` format so captures can be opened in Wireshark
- Add a packet rate counter (packets per second)

---

## Legal / Ethical Notice

This tool is intended for use **only on networks you own or have explicit permission to monitor**. Capturing traffic on networks without authorization is illegal in most jurisdictions. Use responsibly.

---
