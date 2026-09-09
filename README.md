cat << 'EOF' > README.md
# Python Packet Sniffer & Packet Analyzer

A beginner-friendly network packet sniffer built with **Python and Scapy**.

The project captures network packets, identifies common protocols, displays useful packet information, saves the original packets as `.pcap`, and stores searchable packet metadata in a **SQLite database**.

## Features

- Capture network packets with Scapy
- Detect IPv4 and IPv6 packets
- Detect TCP, UDP, ICMP, and other traffic
- Display:
  - Source IP
  - Destination IP
  - Source port
  - Destination port
  - TCP flags
  - Packet size
  - Payload size
- Save captured packets as `.pcap`
- Read previously saved PCAP files with `rdpcap()`
- Store packet metadata in SQLite
- Search/filter packet information using SQL
- Keep multiple timestamped PCAP captures

## Project Flow

```text
Network Traffic
      |
      v
   Scapy sniff()
      |
      v
Analyze packet
      |
      +-----------> Save original packet to PCAP
      |
      +-----------> Save metadata to SQLite
                           |
                           v
                    Search / Analysis
