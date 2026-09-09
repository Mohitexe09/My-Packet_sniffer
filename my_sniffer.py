from scapy.all import (
    sniff,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    Raw,
    wrpcap,
    rdpcap
)

import sqlite3
from datetime import datetime


# ============================================================
# 1. CREATE / OPEN SQLITE DATABASE
# ============================================================

database = sqlite3.connect("packets.db")

cursor = database.cursor()


# ============================================================
# 2. CREATE PACKETS TABLE
# ============================================================

cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    ip_version TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    protocol TEXT,
    source_port INTEGER,
    destination_port INTEGER,
    tcp_flags TEXT,
    packet_size INTEGER,
    payload_size INTEGER
)
""")


database.commit()


# ============================================================
# 3. LIST TO STORE CAPTURED PACKETS
# ============================================================

captured_packets = []


# ============================================================
# 4. PACKET CALLBACK FUNCTION
# ============================================================

def packet_callback(packet):

    # --------------------------------------------------------
    # Check for IPv4 or IPv6
    # --------------------------------------------------------

    if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return


    # --------------------------------------------------------
    # Get IP information
    # --------------------------------------------------------

    if packet.haslayer(IP):

        ip_version = "IPv4"

        src_ip = packet[IP].src

        dst_ip = packet[IP].dst

    else:

        ip_version = "IPv6"

        src_ip = packet[IPv6].src

        dst_ip = packet[IPv6].dst


    # --------------------------------------------------------
    # Default values
    # --------------------------------------------------------

    protocol = "Other"

    source_port = None

    destination_port = None

    tcp_flags = None

    payload_size = 0


    # --------------------------------------------------------
    # Identify TCP
    # --------------------------------------------------------

    if packet.haslayer(TCP):

        protocol = "TCP"

        source_port = packet[TCP].sport

        destination_port = packet[TCP].dport

        tcp_flags = str(packet[TCP].flags)


    # --------------------------------------------------------
    # Identify UDP
    # --------------------------------------------------------

    elif packet.haslayer(UDP):

        protocol = "UDP"

        source_port = packet[UDP].sport

        destination_port = packet[UDP].dport


    # --------------------------------------------------------
    # Identify ICMP
    # --------------------------------------------------------

    elif packet.haslayer(ICMP):

        protocol = "ICMP"


    # --------------------------------------------------------
    # Check for Raw payload
    # --------------------------------------------------------

    if packet.haslayer(Raw):

        payload_size = len(packet[Raw].load)


    # --------------------------------------------------------
    # Get complete packet size
    # --------------------------------------------------------

    packet_size = len(packet)


    # --------------------------------------------------------
    # Get current time
    # --------------------------------------------------------

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


    # ========================================================
    # 5. DISPLAY PACKET INFORMATION
    # ========================================================

    print("\n" + "=" * 60)

    print("Time         :", timestamp)

    print("IP Version   :", ip_version)

    print("Source IP    :", src_ip)

    print("Destination  :", dst_ip)

    print("Protocol     :", protocol)


    if source_port is not None:

        print("Source Port  :", source_port)

        print("Dest Port    :", destination_port)


    if tcp_flags is not None:

        print("TCP Flags    :", tcp_flags)


    print("Packet Size  :", packet_size, "bytes")

    print("Payload Size :", payload_size, "bytes")


    # ========================================================
    # 6. SAVE PACKET IN PYTHON LIST
    # ========================================================

    captured_packets.append(packet)


    # ========================================================
    # 7. SAVE PACKET INFORMATION INTO SQLITE
    # ========================================================

    cursor.execute("""
    INSERT INTO packets (
        timestamp,
        ip_version,
        source_ip,
        destination_ip,
        protocol,
        source_port,
        destination_port,
        tcp_flags,
        packet_size,
        payload_size
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        ip_version,
        src_ip,
        dst_ip,
        protocol,
        source_port,
        destination_port,
        tcp_flags,
        packet_size,
        payload_size
    ))


    database.commit()


# ============================================================
# 8. START PACKET CAPTURE
# ============================================================

print("=" * 60)

print("        PYTHON PACKET SNIFFER")

print("=" * 60)

print("\n[*] Starting packet capture...")

print("[*] Capture time: 30 seconds")

print("[*] Press Ctrl+C to stop manually.\n")


try:

    sniff(
        prn=packet_callback,
        timeout=30
    )


except KeyboardInterrupt:

    print("\n[*] Stopping sniffer...")


# ============================================================
# 9. SAVE CAPTURED PACKETS TO PCAP
# ============================================================

if captured_packets:

    timestamp = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S"
    )


    filename = f"capture_{timestamp}.pcap"


    wrpcap(
        filename,
        captured_packets
    )


    print("\n[+] PCAP saved:", filename)

    print(
        "[+] Packets captured:",
        len(captured_packets)
    )


    # ========================================================
    # 10. READ THE PCAP WE JUST CREATED
    # ========================================================

    old_packets = rdpcap(filename)


    print(
        "\n[+] Packets read from PCAP:",
        len(old_packets)
    )


    print("\n[*] PCAP packet summaries:")


    for packet in old_packets:

        print(packet.summary())


else:

    print("\n[!] No packets were captured.")


# ============================================================
# 11. SEARCH TCP PACKETS FROM SQLITE
# ============================================================

print("\n" + "=" * 60)

print("TCP PACKETS STORED IN SQLITE")

print("=" * 60)


cursor.execute("""
SELECT
    id,
    source_ip,
    destination_ip,
    source_port,
    destination_port
FROM packets
WHERE protocol = 'TCP'
""")


results = cursor.fetchall()


if results:

    for row in results:

        print(row)

else:

    print("No TCP packets found.")


# ============================================================
# 12. SHOW TOTAL PACKETS IN DATABASE
# ============================================================

cursor.execute("""
SELECT COUNT(*)
FROM packets
""")


total_packets = cursor.fetchone()[0]


print("\n[+] Total packets stored in SQLite:")

print(total_packets)


# ============================================================
# 13. CLOSE DATABASE
# ============================================================

database.close()


print("\n[+] SQLite database closed.")

print("[+] Program finished.")
