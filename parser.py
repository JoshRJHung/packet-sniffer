#!/usr/bin/env python3
"""
parser.py — Packet parsing logic for the packet sniffer
--------------------------------------------------------
This file's only job is to take a raw Scapy packet and extract
all the useful information from it into a clean, readable format.

sniffer.py will import and use the functions defined here.
Keeping this logic separate makes both files easier to read and maintain.
"""

from scapy.all import IP, TCP, UDP, ICMP

WELL_KNOWN_PORTS = {
    20:   "FTP data",       # File Transfer Protocol — data channel
    21:   "FTP control",    # File Transfer Protocol — command channel
    22:   "SSH",            # Secure Shell — encrypted remote login
    23:   "Telnet",         # Unencrypted remote login (old, insecure — flag this!)
    25:   "SMTP",           # Simple Mail Transfer Protocol — sending email
    53:   "DNS",            # Domain Name System — translates domain names to IPs
    67:   "DHCP server",    # Dynamic Host Config Protocol — assigns IP addresses
    68:   "DHCP client",
    80:   "HTTP",           # HyperText Transfer Protocol — unencrypted web traffic
    110:  "POP3",           # Post Office Protocol — receiving email
    143:  "IMAP",           # Internet Message Access Protocol — receiving email
    443:  "HTTPS",          # HTTP Secure — encrypted web traffic (most common)
    445:  "SMB",            # Server Message Block — Windows file sharing
    3306: "MySQL",          # MySQL database
    3389: "RDP",            # Remote Desktop Protocol — Windows remote access
    5900: "VNC",            # Virtual Network Computing — remote desktop
    8080: "HTTP alt",       # Alternative HTTP port (often used for dev servers)
    8443: "HTTPS alt",      # Alternative HTTPS port
}

def lookup_port(port_number):
    """
    Takes a port number and returns a string like "443 (HTTPS)" or just "8888".

    Parameters:
        port_number (int): the port number to look up

    Returns:
        str: port number with service name if known, or just the number if unknown

    How it works:
        .get() is a safe way to look up a key in a dictionary.
        If the key exists, it returns the value.
        If the key does NOT exist, it returns the "default" we provide (None here).
        This is safer than doing WELL_KNOWN_PORTS[port_number] directly,
        because that would crash with a KeyError if the port isn't in our table.
    """
    # Try to find the port in our lookup table
    service_name = WELL_KNOWN_PORTS.get(port_number, None)

    if service_name:
        # Port is recognized — return "443 (HTTPS)"
        return f"{port_number} ({service_name})"
    else:
        # Port is not in our table — just return the number as a string
        return str(port_number)
def get_protocol(packet):
    """
    Determines the transport-layer protocol of a packet.

    Parameters:
        packet: a Scapy packet object captured from the network

    Returns:
        str: "TCP", "UDP", "ICMP", or "OTHER"

    Note:
        packet.haslayer(TCP) checks whether the TCP protocol "layer" exists
        inside this packet. Network packets are like onions — they have multiple
        layers stacked on top of each other:
            Ethernet → IP → TCP → (your data)
        haslayer() lets us peek inside and check if a specific layer is present.
    """
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"

def get_tcp_flags(packet):
    """
    Reads the TCP flags from a TCP packet.
    TCP flags are single-bit signals that control the state of a connection.
    Understanding flags is essential for spotting attacks like SYN floods.

    Parameters:
        packet: a Scapy packet object (should have a TCP layer)

    Returns:
        str: a human-readable string of active flags, e.g. "SYN ACK"
             or an empty string if the packet isn't TCP

    TCP flag meanings:
        SYN  — synchronize, starts a new connection (the "hello")
        ACK  — acknowledgement, confirms received data
        FIN  — finished, closes a connection gracefully
        RST  — reset, closes a connection forcefully (often means something went wrong)
        PSH  — push, tells receiver to process data immediately
        URG  — urgent, rarely used
    """
    # If this packet doesn't have a TCP layer, there are no flags to read
    if not packet.haslayer(TCP):
        return ""

    # packet[TCP].flags is a Scapy "FlagValue" object
    # Converting it to a string gives us something like "SA" (SYN + ACK)
    # We then expand the abbreviations into full names for readability
    raw_flags = str(packet[TCP].flags)

    # This is a dictionary mapping single-letter codes → full flag names
    flag_names = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH",
        "U": "URG",
    }

    # Build a list of flag names that are active in this packet
    # This uses a "list comprehension" — a compact way to build a list with a loop:
    #   [expression  for item in collection  if condition]
    # Translation: "for each letter in raw_flags, if it's in our dictionary,
    #               add its full name to the list"
    active_flags = [flag_names[letter] for letter in raw_flags if letter in flag_names]

    # Join the list into a single string separated by spaces: ["SYN", "ACK"] → "SYN ACK"
    return " ".join(active_flags)

def parse_packet(packet):
    """
    The main function of this file. Takes a raw Scapy packet and returns
    a dictionary containing all the useful fields we want to display or log.

    Parameters:
        packet: a Scapy packet object captured from the network

    Returns:
        dict: a dictionary with parsed packet info, or None if the packet
              has no IP layer (e.g. ARP packets — we skip those)

    The dictionary this returns looks like:
        {
            "src_ip":    "192.168.1.5",
            "dst_ip":    "142.250.80.46",
            "protocol":  "TCP",
            "src_port":  "52341",
            "dst_port":  "443 (HTTPS)",
            "flags":     "SYN",
            "size":      74,
            "ttl":       64,
        }
    """
    # If the packet has no IP layer, we can't do much with it — skip it
    # "return None" means "return nothing / no result"
    if not packet.haslayer(IP):
        return None

    # ── Extract the IP layer fields ───────────────────────────────────────────
    #
    # packet[IP] accesses the IP layer of the packet (like peeling the onion).
    # .src and .dst are attributes of that layer — the source and destination IPs.
    # .ttl is "time to live" — a number that decreases at each router hop.
    #       If TTL reaches 0, the packet is discarded. Useful for traceroute.
    #
    src_ip   = packet[IP].src
    dst_ip   = packet[IP].dst
    ttl      = packet[IP].ttl
    protocol = get_protocol(packet)

    # ── Extract port numbers (only exist in TCP and UDP) ──────────────────────
    #
    # We use lookup_port() to add the service name if we recognize the port.
    # .sport = source port (the port the sender is using)
    # .dst   = destination port (the port the receiver is listening on)
    #
    if packet.haslayer(TCP):
        src_port = lookup_port(packet[TCP].sport)
        dst_port = lookup_port(packet[TCP].dport)
    elif packet.haslayer(UDP):
        src_port = lookup_port(packet[UDP].sport)
        dst_port = lookup_port(packet[UDP].dport)
    else:
        # ICMP and other protocols don't use ports
        src_port = "N/A"
        dst_port = "N/A"

    # ── Extract TCP flags (empty string if not TCP) ───────────────────────────
    flags = get_tcp_flags(packet)

    # ── Get the total packet size in bytes ────────────────────────────────────
    # len() on a Scapy packet returns its total size in bytes
    size = len(packet)

    # ── Bundle everything into a dictionary and return it ─────────────────────
    #
    # This is a dictionary literal — we define all the key:value pairs at once.
    # The calling code (sniffer.py) will access individual fields like:
    #     info = parse_packet(packet)
    #     print(info["src_ip"])     →   "192.168.1.5"
    #     print(info["dst_port"])   →   "443 (HTTPS)"
    #
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
