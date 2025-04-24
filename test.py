import unittest
import struct
from unittest.mock import patch, MagicMock
from main import (ethernet_frame, get_mac_address, ipv4_packet, ipv4, icmp_packet, 
                  tcp_segment, udp_segment, format_mult_line)

class TestPacketSniffer(unittest.TestCase):

    def test_get_mac_address(self):
        mac_bytes = b'\xaa\xbb\xcc\xdd\xee\xff'
        self.assertEqual(get_mac_address(mac_bytes), 'AA:BB:CC:DD:EE:FF')
    
    def test_ipv4(self):
        ip_bytes = b'\xc0\xa8\x01\x01'
        self.assertEqual(ipv4(ip_bytes), '192.168.1.1')
    
    def test_format_mult_line(self):
        data = b'\x01\x02\x03\x04'
        expected = r'\x01\x02\x03\x04'
        self.assertEqual(format_mult_line('', data), expected)
