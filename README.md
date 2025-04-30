# Packet Sniffer
## Overview
This Python script is a simple packet sniffer that captures and analyzes network traffic at the Ethernet frame level. It can decode and display various protocol information including Ethernet frames, IPv4 packets, ICMP, TCP, and UDP segments.

## Features
- Captures raw network packets using socket in raw mode
- Decodes Ethernet frames with MAC addresses
- Parses IPv4 packets including version, header length, TTL and protocol
- Handles three common transport protocols:
    - ICMP (protocol 1)
    - TCP (protocol 6)
    - UDP (protocol 17)
- Human-readable output formatting with proper indentation
- MAC and IPv4 address formatting

## Requirements
- Python 3.x
- Root/Administrator privileges (required for raw socket address)

## Usage
1. Run the script with administrative privileges: ``` sudo python3 main.py ```
2. The script will start capturing and displaying network packets in real time
3. Output includes:
    - Ethernet frame information (source/destination MAC, protocol)
    - IPv4 packet details (when protocol is IPv4)
    - Protocol-specific details for ICMP, TCP and UDP
    - Raw data in hexadecimal format

## Code Structure
- ```main()```: Main loop that captures packets and routes them to appropriate parsers
- ```ethernet_frame()```: Unpacks Ethernet frame headers
- ```ipv4_packet()```: Unpacks IPv4 packet headers
- ```icmp_packet()```: Unpacks ICMP packet headers
- ```tcp_segment()```: Unpacks TCP segment headers
- ```udp_segment()```: Unpacks UDP segment headers
- Helper functions:
    - ```get_mac_address()```: Formats MAC addresses
    - ```ipv4()```: Formats IPv4 addresses
    - ```format_mult_line()```: Formats data for readable output

## Limitations
- Currently only handles IPv4 traffic (not IPv6)
- Limited protocol support (only ICMP, TCP and UDP)
- Requires root privileges which may pose security risks
- No packet filtering capabilities (captures all traffic)

## Security Note
Running packet sniffers may violate privacy policies or laws in some jurisdictions. Only use this tool on networks you own or have permission to monitor. The author assumes no responsibility for misuse of this tool.

## Example Output
```
Ethernet Frame:
Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8
IPv4 Packet:
    - Version: 4, Header Length: 20, TTL: 64, Protocol: 6, Source: 192.168.1.1, Target: 192.168.1.2
    - TCP Segment:
        - Source Port: 443, Destination Port: 54321, Sequence: 123456, Acknowledgement: 654321, Flags:
            - URG: 0, ACK: 1, PSH: 0, RST: 0, SYN: 0, FIN: 0
        - Data:
            \x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64
```
