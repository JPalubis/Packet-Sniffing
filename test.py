import unittest
import struct
from unittest.mock import patch, MagicMock
from main import (ethernet_frame, get_mac_address, ipv4_packet, ipv4, icmp_packet, 
                  tcp_segment, udp_segment, format_mult_line)

class TestPacketSniffer(unittest.TestCase):

    # Helper function tests
    def test_get_mac_address(self):
        mac_bytes = b'\xaa\xbb\xcc\xdd\xee\xff'
        self.assertEqual(get_mac_address(mac_bytes), 'AA:BB:CC:DD:EE:FF')
    
    def test_ipv4(self):
        ip_bytes = b'\xc0\xa8\x01\x01'
        self.assertEqual(ipv4(ip_bytes), '192.168.1.1')
    
    def test_format_mult_line_bytes(self):
        data = b'\x01\x02\x03\x04'
        expected = r'\x01\x02\x03\x04'
        self.assertEqual(format_mult_line('', data), expected)
    
    def test_format_mult_line_string(self):
        data = 'A' * 100
        result = format_mult_line('', data, size = 20)
        self.assertTrue(all(len(line) <= 20 for line in result.split('\n')))
    

    # Ethernet frame tests
    def test_ethernet_frame(self):
        destination_mac = b'\xaa\xaa\xaa\xaa\xaa\xaa'
        source_mac = b'\xbb\xbb\xbb\xbb\xbb\xbb'
        protocol = 0x0800
        payload = b'\x00' * 46 # This is the minimum ethernet payload

        frame = destination_mac + source_mac + struct.pack('!H', protocol) + payload
        d_mac, s_mac, proto, data = ethernet_frame(frame)

        self.assertEqual(d_mac, 'AA:AA:AA:AA:AA:AA')
        self.assertEqual(s_mac, 'BB:BB:BB:BB:BB:BB')
        self.assertEqual(proto, 0x0800)
        self.assertEqual(data, payload)
    
    def test_ethernet_frame_short(self):
        with self.assertRaises(struct.error):
            ethernet_frame(b'\x00' * 13) # This should be too short
    

    # IPv4 packet tests
    def test_ipv4_packet(self):
        version_ihl, dscp_ecn, total_length, identification, flags_frag_offset = 0x45, 0, 20, 0, 0
        ttl, protocol, checksum = 64, 6, 0
        source_ip = b'\xc0\xa8\x01\x01' # 192.168.1.1
        destination_ip = b'\xc0\xa8\x01\x02' # 192.168.1.2
        payload = b''

        ip_header = struct.pack('!BBHHHBBH4s4s', version_ihl, dscp_ecn, total_length, 
                                identification, flags_frag_offset, ttl, protocol, checksum, 
                                source_ip, destination_ip)
        
        verion, hlen, ttl, proto, source, destination, data = ipv4_packet(ip_header + payload)

        self.assertEqual(verion, 4)
        self.assertEqual(hlen, 20)
        self.assertEqual(ttl, 64)
        self.assertEqual(proto, 6)
        self.assertEqual(source, '192.168.1.1')
        self.assertEqual(destination, '192.168.1.2')
        self.assertEqual(data, payload)
    
    def test_ipv4_packet_with_options(self):
        version_ihl = 0x46 #Version 4, IHL 6 (24 bytes)
        ip_header = struct.pack('!BBHHHBBH4s4s4s', version_ihl, 0, 24, 0, 0, 64, 6, 0, 
                                b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02', b'\x00\x00\x00\x00')
        
        version, hlen, _, _, _, _, _ = ipv4_packet(ip_header)
        self.assertEqual(version, 4)
        self.assertEqual(hlen, 24)
    

    # ICMP packet tests
    def test_icmp_packet(self):
        icmp_type, code, checksum, payload = 8, 0, 12345, b'\x00\x01\x02\x03'
        icmp_header = struct.pack('!BBH', icmp_type, code, checksum)
        packet = icmp_header + payload

        type_, code_, checksum_, data = icmp_packet(packet)

        self.assertEqual(type_, 8)
        self.assertEqual(code_, 0)
        self.assertEqual(checksum_, 12345)
        self.assertEqual(data, payload)
    

    # TCP segment tests
    def test_tcp_segment(self):
        source_port, destination_port, sequence_num, acknowledge_num = 12345, 80, 1000, 2000
        data_offset_res_flags = 0x5000
        window, checksum, urgent_ptr = 8192, 0, 0
        payload = b'GET / HTTP/1.1\r\n'

        tcp_header = struct.pack('!HHLLHHHH', source_port, destination_port, sequence_num, 
                                 acknowledge_num, data_offset_res_flags, window, checksum, 
                                 urgent_ptr, payload)
        
        (s_port, d_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data) = tcp_segment(tcp_header + payload)

        self.assertEqual(s_port, 12345)
        self.assertEqual(d_port, 80)
        self.assertEqual(seq, 1000)
        self.assertEqual(ack, 2000)
        self.assertEqual(urg, 0)
        self.assertEqual(ack_flag, 0)
        self.assertEqual(psh, 0)
        self.assertEqual(rst, 0)
        self.assertEqual(syn, 0)
        self.assertEqual(fin, 0)
        self.assertEqual(data, payload)
    
    def test_tcp_segment_with_flags(self):
        # TCP header with SYN + ACK flags
        data_offset_res_flags = 0x5012 # Data offset by 5, SYN=1 and ACK=1

        tcp_header = struct.pack('!HHLLH', 12345, 80, 1000, 2000, data_offset_res_flags)
        (_, _, _, _, _, ack_flag, _, _, syn, fin, _) = tcp_segment(tcp_header + b'')

        self.assertEqual(ack_flag, 1)
        self.assertEqual(syn, 1)
        self.assertEqual(fin, 0)
    

    # UDP segment tests
    def test_udp_segment(self):
        source_port, destination_port, length, payload = 12345, 53, 12, b'\x00\x01\x02\x03'

        udp_header = struct.pack('!HHHH', source_port, destination_port, length, 0) # 0 is the checksum
        packet = udp_header + payload

        s_port, d_port, size, data = udp_segment(packet)

        self.assertEqual(s_port, 12345)
        self.assertEqual(d_port, 53)
        self.assertEqual(size, 12)
        self.assertEqual(data, payload)
    
    # Integration tests
    def test_full_ipv4_tcp_packet(self):
        ethernet_header = (
            b'\xaa\xaa\xaa\xaa\xaa\xaa' # Destination mac
            b'\xbb\xbb\xbb\xbb\xbb\xbb' # Source mac
            b'\x08\x00' # IPv4 protocol
        )

        ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0, 0, 64, 6, 0,
                                b'\xc0\xa8\x01\x01', b'\xc0\xa8\x01\x02')
        tcp_header = struct.pack('!HHLLHHHH', 12345, 80, 1000, 2000, 0x5010, 8192, 0, 0) # ACK flag set
        payload = b'GET / HTTP/1.1\r\n'
        packet = ethernet_header + ip_header + tcp_header + payload

        # Test ethernet frame parsing
        d_mac, s_mac, protocol, data = ethernet_frame(packet)
        self.assertEqual(protocol, 0x0800)

        # Test IPv4 Parsing
        version, hlen, _, ip_protocol, source, destination, data = ipv4_packet(data)
        self.assertEqual(version, 4)
        self.assertEqual(ip_protocol, 6)
        self.assertEqual(source, '192.168.1.1')
        self.assertEqual(destination, '192.168.1.2')

        # Test TCP parsing
        s_port, d_port, _, _, _, ack_flag, _, _, _, _, data = tcp_segment(data)
        self.assertEqual(s_port, 12345)
        self.assertEqual(d_port, 80)
        self.assertEqual(ack_flag, 1)
        self.assertEqual(data, payload)
