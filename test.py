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
