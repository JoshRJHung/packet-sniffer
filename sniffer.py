#!/usr/bin/env python3
"""
Simple packet sniffer built with Scapy.

Usage:
    sudo python3 sniffer.py
    sudo python3 sniffer.py -c 50
    sudo python3 sniffer.py -f tcp
    sudo python3 sniffer.py -ip 192.168.1.1
    sudo python3 sniffer.py -p 80
    sudo python3 sniffer.py -o results.txt
    sudo python3 sniffer.py -f tcp -p 443 -c 100

Requirements:
    pip install scapy
    Run with sudo or administrator privileges
"""

import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff

from parser import parse_packet
from logger import PacketLogger


packet_count = 0
ip_counter = Counter()
logger = None


def process_packet(packet):
    """Handle a captured packet."""
    global packet_count

    info = parse_packet(packet)

    if info is None:
        return

    packet_count += 1

    src_ip = info["src_ip"]
    dst_ip = info["dst_ip"]
    protocol = info["protocol"]
    src_port = info["src_port"]
    dst_port = info["dst_port"]
    flags = info["flags"]
    size = info["size"]

    port_info = f"{src_port} → {dst_port}"
    if flags:
        port_info += f" [{flags}]"

    timestamp = datetime.now().strftime("%H:%M:%S")

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

    if logger:
        logger.log_packet(info, packet_count)


def build_filter(protocol, ip_address, port):
    """Build a BPF filter string from CLI arguments."""
    parts = []

    if protocol:
        parts.append(protocol.lower())

    if ip_address:
        parts.append(f"host {ip_address}")

    if port:
        parts.append(f"port {port}")

    return " and ".join(parts)


def print_summary():
    """Print a summary after capture ends."""
    print("\n" + "═" * 60)
    print(f"  CAPTURE COMPLETE — {packet_count} packets captured")
    print("═" * 60)

    if ip_counter:
        print("\n  Top 5 most active IP addresses:")
        for ip, count in ip_counter.most_common(5):
            bar = "█" * min(count, 30)
            print(f"    {ip:<20} {bar} ({count})")

    print()


def main():
    global logger

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

    if args.output:
        logger = PacketLogger(args.output)
        logger.start()

    bpf_filter = build_filter(args.filter, args.ip_address, args.port)

    print("═" * 60)
    print("  PACKET SNIFFER  —  press Ctrl+C to stop")
    print("═" * 60)
    print(f"  Filter   : {bpf_filter if bpf_filter else 'none (capturing all packets)'}")
    print(f"  Limit    : {args.count if args.count > 0 else 'unlimited'}")
    print(f"  Log file : {args.output if args.output else 'none'}")
    print("═" * 60)
    print(f"  {'TIME':<10} {'#':<7} {'PROTO':<6} {'SOURCE':<18}   {'DESTINATION':<18} {'PORTS':<22} SIZE")
    print("─" * 60)

    try:
        sniff(
            prn=process_packet,
            count=args.count,
            filter=bpf_filter,
            store=False,
        )
    except KeyboardInterrupt:
        pass

    print_summary()

    if logger:
        logger.write_summary(ip_counter)
        logger.stop()


if __name__ == "__main__":
    main()
