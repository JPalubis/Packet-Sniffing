import socket
import struct
import textwrap

# Unpack ethernet frame
def ethernet_frame(data):
    # The sender and receiver in the ethernet frame are 6 bytes, and the TYPE is 2 bytes
    destination_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(proto), data[14:]

# Properly format a MAC address (AA:AA:AA:AA:AA:AA)
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()
