import socket
import struct
import textwrap

def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, address = connection.recvfrom(65535) # This is the biggest buffer size
        destination_mac, source_mac, ethernet_protocol, data = ethernet_frame(raw_data)
        print("\nEthernet Frame:")
        print(f"Destination: {destination_mac}, Source: {source_mac}, Protocol: {ethernet_protocol}")

# Unpack ethernet frame
def ethernet_frame(data):
    # The sender and receiver in the ethernet frame are 6 bytes, and the TYPE is 2 bytes
    destination_mac, source_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(destination_mac), get_mac_address(source_mac), socket.htons(proto), data[14:]

# Properly format a MAC address (AA:AA:AA:AA:AA:AA)
def get_mac_address(bytes_address):
    bytes_str = map('{:02x}'.format, bytes_address)
    return ':'.join(bytes_str).upper()


main()
