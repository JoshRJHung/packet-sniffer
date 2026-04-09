#!/usr/bin/env python3
import datetime
import os


class PacketLogger:
    def __init__(self, filename):
        self.filename = filename
        self.file = None
        self.packets_logged = 0
        self.start_time = None

    def start(self):
        self.start_time = datetime.datetime.now()
        self.file = open(self.filename, "w", encoding="utf-8")

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
        if not self.file:
            return

        self.packets_logged += 1

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        port_info = f"{info['src_port']} → {info['dst_port']}"
        if info["flags"]:
            port_info += f" [{info['flags']}]"

        line = (
            f"[{timestamp}] #{packet_number:<5} "
            f"{info['protocol']:<6} "
            f"{info['src_ip']:<18} → {info['dst_ip']:<18} "
            f"{port_info:<35} "
            f"{info['size']} bytes  TTL={info['ttl']}\n"
        )

        self.file.write(line)
        self.file.flush()

    def write_summary(self, ip_counter):
        if not self.file:
            return

        end_time = datetime.datetime.now()
        duration = end_time - self.start_time
        total_seconds = duration.total_seconds()

        summary = (
            f"\n{'═' * 60}\n"
            f"  SUMMARY\n"
            f"{'═' * 60}\n"
            f"  Packets logged : {self.packets_logged}\n"
            f"  Duration       : {total_seconds:.1f} seconds\n"
            f"  Ended          : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
        )

        if ip_counter:
            summary += f"\n  Top 10 most active IP addresses:\n"
            for ip, count in ip_counter.most_common(10):
                bar = "█" * min(count, 40)
                summary += f"    {ip:<22} {bar} ({count})\n"

        summary += f"\n{'═' * 60}\n"

        self.file.write(summary)
        self.file.flush()

    def stop(self):
        if self.file:
            self.file.close()
            self.file = None

            print(f"[*] Log saved to: {os.path.abspath(self.filename)}")
