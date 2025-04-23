import socket
import struct
from textwrap import wrap


# Need tabs to make the ethernet display more human legible
TAB1 = '\t - '
TAB2 = '\t\t - '
TAB3 = '\t\t\t - '
TAB4 = '\t\t\t\t - '

DATA_TAB1 = '\t '
DATA_TAB2 = '\t\t  '
DATA_TAB3 = '\t\t\t '
DATA_TAB4 = '\t\t\t\t '

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connection.recvfrom(65535) # This is the biggest buffer size
        destination_mac, source_mac, ethernet_protocol, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(f"Destination: {destination_mac}, Source: {source_mac}, Protocol: {ethernet_protocol}")

        # Regular internet traffic
        if ethernet_frame == 8:
            (version, header_length, time_to_live, protocol, source, target, data) = ipv4_packet(data)
            print(TAB1 + 'IPv4 Packet:')
            print(TAB2 + f'Version: {version}, Header Length: {header_length}, TTL: {time_to_live} \
                  Protocol: {protocol}, Source: {source}, Target: {target}')
            
            # For ICMP:
            if protocol == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print(TAB1 + 'ICMP Packet:')
                print(TAB2 + f'Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print(TAB2 + 'Data:')
                print(format_mult_line(DATA_TAB3, data))


# Unpack ethernet frame
def ethernet_frame(data):
    # The sender and receiver in the ethernet frame are 6 bytes, and the TYPE is 2 bytes
    destination_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(proto), data[14:]

# Properly format a MAC address (AA:AA:AA:AA:AA:AA)
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_length = (version_header_len & 15) * 4 # Need the header length as it determines 
    # where the data starts
    time_to_live, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) 
    # The argument in the "unpack" is the format the data will be in
    return version, header_length, time_to_live, protocol, ipv4(source), ipv4(target), data[header_length:]

# Used to return properly formatted IPv4 address
def ipv4(address):
    return '.'.join(map(str, address))


# We are only going to unpack ICMP and TCP protocols as they are the vast majority of protocols
# that I am working with

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_segment(data):
    (source_port, destination_port, sequence, acknowledgement, 
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    # We need to bitshift the TCP chunk (offset, reserved, flags) enough to get the 'offset' portion.
    # The chunk is 16 bits long, so we need to bitshift it by 12, and myltiply it by 4 to convert 
    # the WORDS to bytes, since the array is indexed in bytes
    offset = (offset_reserved_flags >> 12) * 4

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_segment(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]

# Need to format all the incoming data to make it more human readable as the data can appear
# to be too long
def format_mult_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in wrap(string, size)])


main()
