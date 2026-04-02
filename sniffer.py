#!/usr/bin/env python3
"""
packet_sniffer - A beginner-friendly network packet sniffer
Author: Josh Hung
Description: Captures and displays live network packets using Scapy.
             Supports filtering by protocol, IP, and port.
             Optionally logs results to a file.

Usage:
    sudo python3 sniffer.py                         # capture all packets
    sudo python3 sniffer.py -c 50                   # capture 50 packets then stop
    sudo python3 sniffer.py -f tcp                  # capture only TCP packets
    sudo python3 sniffer.py -ip 192.168.1.1         # filter by IP address
    sudo python3 sniffer.py -p 80                   # filter by port
    sudo python3 sniffer.py -o results.txt          # save output to file
    sudo python3 sniffer.py -f tcp -p 443 -c 100    # combine filters

Requirements:
    pip install scapy
    Must be run with sudo / administrator privileges
"""

import argparse
import datetime
from collections import Counter

# Scapy — we only need sniff() now, since parser.py handles the packet inspection
from scapy.all import sniff

# This is how you import from your OWN files.
# "from parser import parse_packet" means:
#   → look in parser.py (in the same folder)
#   → grab the function called parse_packet
#   → make it available to use in this file
#
# After this line, we can call parse_packet() just like any built-in function.
from parser import parse_packet

# Import the PacketLogger class from logger.py
# Same pattern as before — "from filename import ClassName"
from logger import PacketLogger


# ─── Globals (used to track stats across all captured packets) ────────────────

packet_count = 0
ip_counter   = Counter()   # tracks how many packets each IP sends/receives

# logger holds our PacketLogger instance — None until the user passes -o flag.
# Using the class from logger.py replaces the raw file handle we had before.
logger = None


# ─── Packet Parser ────────────────────────────────────────────────────────────

def process_packet(packet):
    """
    Called automatically by Scapy for each captured packet.
    Delegates parsing to parser.py and logging to logger.py.
    """
    global packet_count

    info = parse_packet(packet)

    if info is None:
        return

    packet_count += 1

    src_ip   = info["src_ip"]
    dst_ip   = info["dst_ip"]
    protocol = info["protocol"]
    src_port = info["src_port"]
    dst_port = info["dst_port"]
    flags    = info["flags"]
    size     = info["size"]

    port_info = f"{src_port} → {dst_port}"
    if flags:
        port_info += f" [{flags}]"

    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    ip_counter[src_ip] += 1
    ip_counter[dst_ip] += 1

    line = (
        f"[{timestamp}] #{packet_count:<5} "
        f"{protocol:<6} "
        f"{src_ip:<18} → {dst_ip:<18} "
        f"{port_info:<35} "
        f"{size} bytes"
    )

    print(line)

    # If a logger is active, hand it the parsed info dictionary.
    # Notice we pass "info" (the whole dictionary) rather than a formatted string —
    # logger.py builds its own formatted line, which lets it include extra fields
    # like TTL that the terminal display doesn't show.
    if logger:
        logger.log_packet(info, packet_count)


# ─── Filter Builder ───────────────────────────────────────────────────────────

def build_filter(protocol, ip_address, port):
    """
    Builds a BPF (Berkeley Packet Filter) string from the CLI arguments.
    BPF is the standard filter syntax used by packet capture tools like Wireshark and tcpdump.
    """
    parts = []

    if protocol:
        parts.append(protocol.lower())      # e.g. "tcp"

    if ip_address:
        parts.append(f"host {ip_address}")  # e.g. "host 192.168.1.1"

    if port:
        parts.append(f"port {port}")        # e.g. "port 443"

    return " and ".join(parts)  # combine: "tcp and host 192.168.1.1 and port 443"


# ─── Summary Report ───────────────────────────────────────────────────────────

def print_summary():
    """Prints a summary after capture ends (Ctrl+C or packet limit reached)."""
    print("\n" + "═" * 60)
    print(f"  CAPTURE COMPLETE — {packet_count} packets captured")
    print("═" * 60)

    if ip_counter:
        print("\n  Top 5 most active IP addresses:")
        for ip, count in ip_counter.most_common(5):
            bar = "█" * min(count, 30)   # simple ASCII bar chart
            print(f"    {ip:<20} {bar} ({count})")

    print()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    global logger

    # ── Argument parser (handles command-line flags) ──────────────────────────
    parser = argparse.ArgumentParser(
        description="A simple network packet sniffer built with Scapy"
    )
    parser.add_argument(
        "-c", "--count",
        type=int, default=0,
        help="Number of packets to capture (0 = unlimited, default)"
    )
    parser.add_argument(
        "-f", "--filter",
        type=str, default=None,
        choices=["tcp", "udp", "icmp"],
        help="Filter by protocol: tcp, udp, or icmp"
    )
    parser.add_argument(
        "-ip", "--ip-address",
        type=str, default=None,
        help="Filter by source or destination IP address"
    )
    parser.add_argument(
        "-p", "--port",
        type=int, default=None,
        help="Filter by port number"
    )
    parser.add_argument(
        "-o", "--output",
        type=str, default=None,
        help="Save captured packets to a text file"
    )

    args = parser.parse_args()

    # ── Set up the logger if -o flag was provided ─────────────────────────────
    # This replaces the old open() call.
    # We create a PacketLogger instance and call .start() to open the file.
    if args.output:
        logger = PacketLogger(args.output)
        logger.start()

    # ── Build the BPF filter string ───────────────────────────────────────────
    bpf_filter = build_filter(args.filter, args.ip_address, args.port)

    # ── Print startup banner ──────────────────────────────────────────────────
    print("═" * 60)
    print("  PACKET SNIFFER  —  press Ctrl+C to stop")
    print("═" * 60)
    print(f"  Filter   : {bpf_filter if bpf_filter else 'none (capturing all packets)'}")
    print(f"  Limit    : {args.count if args.count > 0 else 'unlimited'}")
    print(f"  Log file : {args.output if args.output else 'none'}")
    print("═" * 60)
    print(f"  {'TIME':<10} {'#':<7} {'PROTO':<6} {'SOURCE':<18}   {'DESTINATION':<18} {'PORTS':<22} SIZE")
    print("─" * 60)

    # ── Start sniffing ────────────────────────────────────────────────────────
    try:
        sniff(
            prn=process_packet,       # call process_packet() for each packet
            count=args.count,         # 0 means capture forever
            filter=bpf_filter,        # BPF filter string (empty = no filter)
            store=False               # don't store packets in memory (saves RAM)
        )
    except KeyboardInterrupt:
        pass   # user pressed Ctrl+C — that's fine, just show the summary

    # ── Cleanup and summary ───────────────────────────────────────────────────
    print_summary()

    # If we were logging, write the summary to the file then close it.
    # We pass ip_counter so the file summary includes the top IPs section.
    if logger:
        logger.write_summary(ip_counter)
        logger.stop()


if __name__ == "__main__":
    main()
