#!/usr/bin/env python3
"""
Netpulse Synthetic PCAP Generator
Produces deterministic network capture fixtures conforming to RFC 5737 (TEST-NET)
and RFC 8701 (GREASE).
"""

import struct
import os

def checksum_inet(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f'!{len(data)//2}H', data))
    while (s >> 16):
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def make_eth(dst_mac: bytes, src_mac: bytes, ethertype: int) -> bytes:
    return dst_mac + src_mac + struct.pack('!H', ethertype)

def make_arp(opcode: int, sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str) -> bytes:
    sip = bytes(int(x) for x in sender_ip.split('.'))
    tip = bytes(int(x) for x in target_ip.split('.'))
    return struct.pack('!HHBBH', 1, 0x0800, 6, 4, opcode) + sender_mac + sip + target_mac + tip

def make_ipv4(src_ip: str, dst_ip: str, proto: int, payload: bytes, ip_id: int = 1) -> bytes:
    ver_ihl = (4 << 4) | 5
    tos = 0
    total_len = 20 + len(payload)
    flags_frag = 0x4000 # Don't fragment
    ttl = 64
    sip = bytes(int(x) for x in src_ip.split('.'))
    dip = bytes(int(x) for x in dst_ip.split('.'))
    hdr_no_cksum = struct.pack('!BBHHHBBH', ver_ihl, tos, total_len, ip_id, flags_frag, ttl, proto, 0) + sip + dip
    cksum = checksum_inet(hdr_no_cksum)
    hdr = struct.pack('!BBHHHBBH', ver_ihl, tos, total_len, ip_id, flags_frag, ttl, proto, cksum) + sip + dip
    return hdr + payload

def make_tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes = b'', win: int = 65535) -> bytes:
    data_offset = (5 << 4)
    tcp_hdr = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, data_offset, flags, win, 0, 0)
    return tcp_hdr + payload

def make_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    return struct.pack('!HHHH', src_port, dst_port, length, 0) + payload

def make_dns_query(qname: str, qtype: int = 1, tx_id: int = 0x1234) -> bytes:
    flags = 0x0100 # Standard query, recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    hdr = struct.pack('!HHHHHH', tx_id, flags, qdcount, ancount, nscount, arcount)

    qname_bytes = b''
    for part in qname.split('.'):
        if part:
            qname_bytes += bytes([len(part)]) + part.encode('ascii')
    qname_bytes += b'\x00'

    tail = struct.pack('!HH', qtype, 1) # Type, Class IN
    return hdr + qname_bytes + tail

def make_dns_response(qname: str, rdata_ip: str, tx_id: int = 0x1234) -> bytes:
    flags = 0x8180 # Standard response, recursion desired, recursion available
    hdr = struct.pack('!HHHHHH', tx_id, flags, 1, 1, 0, 0)

    qname_bytes = b''
    for part in qname.split('.'):
        if part:
            qname_bytes += bytes([len(part)]) + part.encode('ascii')
    qname_bytes += b'\x00'
    qtail = struct.pack('!HH', 1, 1)

    # Answer: pointer to qname offset 12 (0xc00c)
    ans_ptr = struct.pack('!H', 0xc00c)
    ans_meta = struct.pack('!HHIH', 1, 1, 300, 4)
    rdata = bytes(int(x) for x in rdata_ip.split('.'))

    return hdr + qname_bytes + qtail + ans_ptr + ans_meta + rdata

def make_tls_client_hello() -> bytes:
    client_version = 0x0303 # TLS 1.2
    random_bytes = b'\x42' * 32
    session_id = b'\x01\x02\x03\x04'
    session_id_field = bytes([len(session_id)]) + session_id

    # Cipher suites with GREASE 0x1a1a
    ciphers = [0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f]
    ciphers_bytes = struct.pack('!H', len(ciphers) * 2) + b''.join(struct.pack('!H', c) for c in ciphers)

    comp_methods = b'\x01\x00' # length 1, null compression

    # Extensions:
    # 0x0000: SNI (secure.test-net.org)
    sni_host = b'secure.test-net.org'
    sni_data = struct.pack('!H', len(sni_host) + 3) + b'\x00' + struct.pack('!H', len(sni_host)) + sni_host
    ext_sni = struct.pack('!HH', 0x0000, len(sni_data)) + sni_data

    # 0x000a: Supported Groups (curves) with GREASE 0x2a2a, X25519 (29), secp256r1 (23)
    curves = [0x2a2a, 29, 23]
    curves_payload = struct.pack('!H', len(curves) * 2) + b''.join(struct.pack('!H', c) for c in curves)
    ext_curves = struct.pack('!HH', 0x000a, len(curves_payload)) + curves_payload

    # 0x000b: EC Point Formats
    ec_pf_payload = b'\x01\x00' # len 1, uncompressed (0)
    ext_ec_pf = struct.pack('!HH', 0x000b, len(ec_pf_payload)) + ec_pf_payload

    # 0x0010: ALPN (h2, http/1.1)
    alpn_payload = struct.pack('!H', 12) + b'\x02h2\x08http/1.1'
    ext_alpn = struct.pack('!HH', 0x0010, len(alpn_payload)) + alpn_payload

    # 0x3a3a: GREASE extension
    ext_grease = struct.pack('!HH', 0x3a3a, 0)

    extensions_content = ext_grease + ext_sni + ext_curves + ext_ec_pf + ext_alpn
    extensions_field = struct.pack('!H', len(extensions_content)) + extensions_content

    ch_body = struct.pack('!H', client_version) + random_bytes + session_id_field + ciphers_bytes + comp_methods + extensions_field
    ch_hdr = b'\x01' + struct.pack('!I', len(ch_body))[1:] # 3-byte length
    handshake = ch_hdr + ch_body

    # TLS Record Header
    rec_hdr = struct.pack('!BHH', 0x16, 0x0301, len(handshake))
    return rec_hdr + handshake

def make_dhcp_request(client_mac: bytes) -> bytes:
    # BOOTP: op=1, htype=1, hlen=6, hops=0, xid=0x3903f326, secs=0, flags=0
    hdr = struct.pack('!BBBBIHHIIII', 1, 1, 6, 0, 0x3903f326, 0, 0, 0, 0, 0, 0)
    chaddr = client_mac + (b'\x00' * 10)
    sname = b'\x00' * 64
    file_f = b'\x00' * 128
    cookie = b'\x63\x82\x53\x63' # Magic cookie

    # Options
    opt53 = b'\x35\x01\x03' # Option 53 (DHCP Request)
    opt12_val = b'workstation-node'
    opt12 = b'\x0c' + bytes([len(opt12_val)]) + opt12_val
    opt55_val = bytes([1, 121, 33, 3, 6, 12, 15, 26, 28, 42, 119]) # Linux fingerprint
    opt55 = b'\x37' + bytes([len(opt55_val)]) + opt55_val
    opt_end = b'\xff'

    options = opt53 + opt12 + opt55 + opt_end
    return hdr + chaddr + sname + file_f + cookie + options

def generate_pcap(output_path: str):
    # PCAP Global Header: magic 0xa1b2c3d4, version 2.4, thiszone 0, sigfigs 0, snaplen 65535, network 1 (Ethernet)
    global_hdr = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    packets = []
    base_ts = 1700000000

    mac_vmware = b'\x00\x50\x56\x11\x22\x33'
    mac_client = b'\x00\x0c\x29\xaa\xbb\xcc'
    mac_bcast  = b'\xff\xff\xff\xff\xff\xff'
    mac_rpi_attacker = b'\xb8\x27\xeb\xde\xad\x01'
    mac_dns_srv = b'\x00\x0c\xe6\x55\x66\x77'

    # Packet 1: Normal ARP Request (Who has 192.0.2.1? Tell 192.0.2.10)
    p1_eth = make_eth(mac_bcast, mac_client, 0x0806)
    p1_arp = make_arp(1, mac_client, "192.0.2.10", b'\x00'*6, "192.0.2.1")
    packets.append((base_ts, 100000, p1_eth + p1_arp))

    # Packet 2: Normal ARP Reply (192.0.2.1 is at 00:50:56:11:22:33)
    p2_eth = make_eth(mac_client, mac_vmware, 0x0806)
    p2_arp = make_arp(2, mac_vmware, "192.0.2.1", mac_client, "192.0.2.10")
    packets.append((base_ts, 105000, p2_eth + p2_arp))

    # Packet 3: Attacker Gratuitous ARP Poisoning (192.0.2.1 is now at b8:27:eb:de:ad:01)
    p3_eth = make_eth(mac_bcast, mac_rpi_attacker, 0x0806)
    p3_arp = make_arp(2, mac_rpi_attacker, "192.0.2.1", mac_bcast, "192.0.2.1")
    packets.append((base_ts, 200000, p3_eth + p3_arp))

    # Packet 4: Normal DNS Query for api.service.test-net.org
    dns_query_normal = make_dns_query("api.service.test-net.org", qtype=1, tx_id=0x1001)
    udp_dns_1 = make_udp(53001, 53, dns_query_normal)
    ip_dns_1 = make_ipv4("192.0.2.10", "198.51.100.53", 17, udp_dns_1, ip_id=101)
    p4_eth = make_eth(mac_dns_srv, mac_client, 0x0800)
    packets.append((base_ts + 1, 50000, p4_eth + ip_dns_1))

    # Packet 5: Normal DNS Response
    dns_resp_normal = make_dns_response("api.service.test-net.org", "198.51.100.100", tx_id=0x1001)
    udp_dns_2 = make_udp(53, 53001, dns_resp_normal)
    ip_dns_2 = make_ipv4("198.51.100.53", "192.0.2.10", 17, udp_dns_2, ip_id=102)
    p5_eth = make_eth(mac_client, mac_dns_srv, 0x0800)
    packets.append((base_ts + 1, 55000, p5_eth + ip_dns_2))

    # Packet 6: DNS Exfiltration Tunnel Query (high entropy & high hex ratio)
    exfil_domain = "4a6f686e446f65536563726574446174613132333435363738.tunnel.test-net.org"
    dns_query_exfil = make_dns_query(exfil_domain, qtype=16, tx_id=0x2002) # qtype 16 = TXT
    udp_dns_3 = make_udp(53002, 53, dns_query_exfil)
    ip_dns_3 = make_ipv4("192.0.2.20", "198.51.100.53", 17, udp_dns_3, ip_id=103)
    p6_eth = make_eth(mac_dns_srv, mac_client, 0x0800)
    packets.append((base_ts + 1, 120000, p6_eth + ip_dns_3))

    # Packet 7: TCP SYN
    tcp_syn = make_tcp(49152, 443, seq=1000, ack=0, flags=0x02) # SYN
    ip_syn = make_ipv4("192.0.2.10", "198.51.100.20", 6, tcp_syn, ip_id=201)
    p7_eth = make_eth(mac_vmware, mac_client, 0x0800)
    packets.append((base_ts + 2, 10000, p7_eth + ip_syn))

    # Packet 8: TCP SYN-ACK
    tcp_synack = make_tcp(443, 49152, seq=5000, ack=1001, flags=0x12) # SYN+ACK
    ip_synack = make_ipv4("198.51.100.20", "192.0.2.10", 6, tcp_synack, ip_id=202)
    p8_eth = make_eth(mac_client, mac_vmware, 0x0800)
    packets.append((base_ts + 2, 15000, p8_eth + ip_synack))

    # Packet 9: TLS ClientHello
    tls_payload = make_tls_client_hello()
    tcp_tls = make_tcp(49152, 443, seq=1001, ack=5001, flags=0x18, payload=tls_payload) # 0x18 = PSH+ACK
    ip_tls = make_ipv4("192.0.2.10", "198.51.100.20", 6, tcp_tls, ip_id=203)
    p9_eth = make_eth(mac_vmware, mac_client, 0x0800)
    packets.append((base_ts + 2, 20000, p9_eth + ip_tls))

    # Packet 10: DHCP Request (Linux Option 55 fingerprint)
    dhcp_payload = make_dhcp_request(mac_client)
    udp_dhcp = make_udp(68, 67, dhcp_payload)
    ip_dhcp = make_ipv4("0.0.0.0", "255.255.255.255", 17, udp_dhcp, ip_id=301)
    p10_eth = make_eth(mac_bcast, mac_client, 0x0800)
    packets.append((base_ts + 3, 5000, p10_eth + ip_dhcp))

    # Write PCAP file
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(global_hdr)
        for ts_sec, ts_usec, pkt_bytes in packets:
            incl_len = len(pkt_bytes)
            orig_len = len(pkt_bytes)
            pkt_hdr = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
            f.write(pkt_hdr + pkt_bytes)

    print(f"[GENERATOR] Deterministic capture fixture generated: {output_path} ({len(packets)} packets)")

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, 'synthetic_capture.pcap')
    generate_pcap(target)
