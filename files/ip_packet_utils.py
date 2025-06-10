# ip_packet_utils.py
import socket
import struct

def calculate_checksum(data):
    if len(data) % 2:
        data += b'\x00'
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF

def create_ip_header(source_ip, dest_ip, payload_len, ttl=64, frag_offset=0):
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    tos = 0
    total_length = 20 + payload_len
    identification = 54321
    flags_offset = (0 << 13) + frag_offset
    protocol = socket.IPPROTO_TCP
    checksum = 0  # initial
    source_addr = socket.inet_aton(source_ip)
    dest_addr = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_offset,
        ttl,
        protocol,
        checksum,
        source_addr,
        dest_addr
    )

    checksum = calculate_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_offset,
        ttl,
        protocol,
        checksum,
        source_addr,
        dest_addr
    )

    return ip_header
