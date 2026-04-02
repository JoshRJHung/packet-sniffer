#!/usr/bin/env python3
"""
logger.py — Logging logic for the packet sniffer
-------------------------------------------------
This file's job is to handle everything related to saving captured
packet data to a file on disk.

Currently sniffer.py does its own basic logging with open() and file.write().
This file replaces that with a dedicated Logger class that is cleaner,
safer, and easier to expand later.

sniffer.py will import and use the PacketLogger class defined here.
"""

import datetime
import os


# ─── What is a Class? ─────────────────────────────────────────────────────────
#
# So far we've only used functions — reusable blocks of code that do one job.
# A CLASS is the next level up: it's a blueprint for creating an OBJECT that
# bundles together related data AND the functions that operate on that data.
#
# Real-world analogy:
#   A "Car" class is a blueprint. Every car has:
#       - Data (attributes): color, speed, fuel_level
#       - Actions (methods): accelerate(), brake(), refuel()
#
#   When you build an actual car from that blueprint, that's called an INSTANCE.
#   You can build many instances from one class:
#       my_car    = Car("red")
#       your_car  = Car("blue")
#
# In our case, PacketLogger is a blueprint for a logger object that has:
#   - Data:    filename, the open file handle, a packet counter
#   - Actions: start(), log_packet(), write_summary(), stop()
#
# Why use a class instead of plain functions?
#   Because the logger needs to REMEMBER STATE between calls —
#   it needs to keep the file open and track how many packets it has written.
#   A class is the natural way to hold that persistent data.
#
# Syntax:
#   class ClassName:
#       def __init__(self, ...):    ← the "constructor" — runs when you create an instance
#           self.attribute = value  ← "self" refers to THIS specific instance
#
#       def method_name(self, ...): ← a function that belongs to the class
#           ...
# ─────────────────────────────────────────────────────────────────────────────


class PacketLogger:
    """
    Handles writing captured packet data to a log file.

    Usage in sniffer.py:
        logger = PacketLogger("results.txt")  # create an instance
        logger.start()                         # open the file
        logger.log_packet(info)                # write a packet
        logger.stop()                          # close the file + write summary
    """

    def __init__(self, filename):
        """
        The constructor — called automatically when you do PacketLogger("results.txt").
        Sets up the initial state of this logger instance.

        Parameters:
            filename (str): the path to the file we want to write to

        "self" is a reference to THIS specific instance of PacketLogger.
        Every attribute we want the object to remember is stored as self.something.
        """
        # Store the filename so other methods can access it later
        self.filename = filename

        # The file handle — None for now, set to an actual file in start()
        # We keep this as an attribute so every method can access the same open file
        self.file = None

        # Track how many packets we've logged (for the summary at the end)
        self.packets_logged = 0

        # Record when logging started (used in the file header and summary)
        self.start_time = None


    def start(self):
        """
        Opens the log file for writing and writes a header at the top.
        Call this once before you start capturing packets.

        ── What is a Context Manager / "with" statement? ─────────────────────
        You may have seen this pattern:
            with open("file.txt", "w") as f:
                f.write("hello")

        The "with" statement is a context manager — it automatically handles
        setup AND cleanup. When the "with" block ends (or if an error occurs),
        Python automatically closes the file for you.

        We're NOT using "with" here because we want the file to stay open
        across many separate method calls (one per packet). Instead we manually
        open it in start() and close it in stop().

        File modes:
            "w"  — write mode: creates the file if it doesn't exist,
                   OVERWRITES it if it does
            "a"  — append mode: adds to the end of an existing file
            "r"  — read mode: only reading, no writing
        ─────────────────────────────────────────────────────────────────────
        """
        self.start_time = datetime.datetime.now()

        # Open the file in write mode
        # "encoding='utf-8'" ensures special characters (like →) are saved correctly
        self.file = open(self.filename, "w", encoding="utf-8")

        # Write a header block at the top of the file so it's human-readable
        # The triple-quoted string lets us write multiple lines without \n everywhere
        header = (
            f"{'═' * 60}\n"
            f"  PACKET SNIFFER LOG\n"
            f"  Started : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"  File    : {os.path.abspath(self.filename)}\n"
            f"{'═' * 60}\n\n"
        )

        self.file.write(header)
        self.file.flush()

        print(f"[*] Logging to: {os.path.abspath(self.filename)}")


    def log_packet(self, info, packet_number):
        """
        Writes a single packet's information to the log file.
        Called once per captured packet.

        Parameters:
            info (dict):        the dictionary returned by parse_packet() in parser.py
            packet_number (int): the running count of captured packets

        ── What is a Guard Clause? ───────────────────────────────────────────
        The first line below is called a "guard clause" — it checks whether
        we're in a valid state before doing any work. If the file isn't open
        (maybe start() was never called), we return early instead of crashing.

        This pattern — checking preconditions at the TOP of a function and
        returning early if they fail — keeps the main logic unindented and
        easier to read.
        ─────────────────────────────────────────────────────────────────────
        """
        # Guard clause: if the file isn't open, do nothing
        if not self.file:
            return

        self.packets_logged += 1

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        # ── String formatting with f-strings ──────────────────────────────────
        # The :<N syntax pads a value to N characters wide (left-aligned).
        # This keeps columns lined up neatly even when values are different lengths.
        #   f"{'TCP':<6}"   →   "TCP   "  (padded to 6 chars)
        #   f"{'HTTPS':<6}" →   "HTTPS "  (padded to 6 chars)
        # ─────────────────────────────────────────────────────────────────────

        # Build the port + flags string (same logic as sniffer.py)
        port_info = f"{info['src_port']} → {info['dst_port']}"
        if info["flags"]:
            port_info += f" [{info['flags']}]"

        # Main packet line
        line = (
            f"[{timestamp}] #{packet_number:<5} "
            f"{info['protocol']:<6} "
            f"{info['src_ip']:<18} → {info['dst_ip']:<18} "
            f"{port_info:<35} "
            f"{info['size']} bytes  TTL={info['ttl']}\n"
        )

        self.file.write(line)

        # flush() forces Python to write buffered data to disk immediately.
        # Without this, data sits in memory and might be lost if the program crashes.
        self.file.flush()


    def write_summary(self, ip_counter):
        """
        Writes a summary report at the bottom of the log file.
        Call this once at the end, before stop().

        Parameters:
            ip_counter (Counter): the Counter object from sniffer.py tracking
                                  how many packets each IP address was involved in
        """
        if not self.file:
            return

        end_time  = datetime.datetime.now()
        duration  = end_time - self.start_time  # this gives a timedelta object

        # ── What is a timedelta? ──────────────────────────────────────────────
        # When you subtract two datetime objects, Python gives you a "timedelta"
        # — an object representing the difference between two moments in time.
        # .total_seconds() converts that into a plain float number of seconds.
        # ─────────────────────────────────────────────────────────────────────
        total_seconds = duration.total_seconds()

        summary = (
            f"\n{'═' * 60}\n"
            f"  SUMMARY\n"
            f"{'═' * 60}\n"
            f"  Packets logged : {self.packets_logged}\n"
            f"  Duration       : {total_seconds:.1f} seconds\n"
            f"  Ended          : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        # Add top IPs section if we have any data
        if ip_counter:
            summary += f"\n  Top 10 most active IP addresses:\n"

            # .most_common(10) returns a list of (ip, count) tuples, sorted by count
            # We unpack each tuple directly in the for loop: "for ip, count in ..."
            # This is called "tuple unpacking" — a clean Python shorthand
            for ip, count in ip_counter.most_common(10):
                bar = "█" * min(count, 40)
                summary += f"    {ip:<22} {bar} ({count})\n"

        summary += f"\n{'═' * 60}\n"

        self.file.write(summary)
        self.file.flush()


    def stop(self):
        """
        Closes the log file. Always call this at the end to make sure
        all data is properly written and the file handle is released.

        Not closing a file is a common beginner bug — the last chunk of
        data may never actually reach the disk if the file isn't closed.
        """
        if self.file:
            self.file.close()

            # Set to None so we don't accidentally try to write to a closed file
            self.file = None

            print(f"[*] Log saved to: {os.path.abspath(self.filename)}")
