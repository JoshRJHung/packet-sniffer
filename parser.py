#!/usr/bin/env python3
"""Packet parsing helpers for the packet sniffer."""

from scapy.all import IP, TCP, UDP, ICMP

WELL_KNOWN_PORTS = {
    20:   "FTP data",
    21:   "FTP control",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP server",
    68:   "DHCP client",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP alt",
    8443: "HTTPS alt",
}


def lookup_port(port_number):
    """Return a port number with a known service name when available."""
    service_name = WELL_KNOWN_PORTS.get(port_number, None)

    if service_name:
        return f"{port_number} ({service_name})"
    return str(port_number)


def get_protocol(packet):
    """Return the transport protocol name for a packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_tcp_flags(packet):
    """Return expanded TCP flag names for a packet."""
    if not packet.haslayer(TCP):
        return ""

    raw_flags = str(packet[TCP].flags)

    flag_names = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }

    active_flags = [flag_names[letter] for letter in raw_flags if letter in flag_names]

    return " ".join(active_flags)


def parse_packet(packet):
    """Extract display-friendly packet details from a Scapy packet."""
    if not packet.haslayer(IP):
        return None

    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    ttl      = packet[IP].ttl
    protocol = get_protocol(packet)

    if packet.haslayer(TCP):
        src_port = lookup_port(packet[TCP].sport)
        dst_port = lookup_port(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = lookup_port(packet[UDP].sport)
        dst_port = lookup_port(packet[UDP].dport)
    else:
        src_port = "N/A"
        dst_port = "N/A"

    flags = get_tcp_flags(packet)
    size = len(packet)

    return {
        "src_ip":   src_ip,
        "dst_ip":   dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags":    flags,
        "size":     size,
        "ttl":      ttl,
    }
