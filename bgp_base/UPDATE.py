from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGPHeader, BGPUpdate, BGPPathAttr, BGPNLRI_IPv4, FlagsField
from scapy.sendrecv import send


"""
_bgp_message_types = {
    0: "NONE",
    1: "OPEN",
    2: "UPDATE",
    3: "NOTIFICATION",
    4: "KEEPALIVE",
    5: "ROUTE-REFRESH"
}
"""
bgp_type = 2
src_ipv4_addr = '192.168.80.1'  # eth0
src_ipv4_addr_byte = b'\xc0\xa8\x50\x01'  # eth0
dst_ipv4_addr = '192.168.80.254'
established_port = 12345    # random port
current_seq_num = 1500  # seq
expected_seq_num = 1000  # ack

NLRI_PREFIX_WITHDRAWN1 = '192.168.1.0/24'
NLRI_PREFIX_WITHDRAWN2 = '192.168.2.0/24'
NLRI_PREFIX1 = '10.110.99.0/24'
NLRI_PREFIX2 = '10.110.100.0/24'

# proto=6 represents that, TCP will be travelling above this layer. This is simple IPV4 communication.
base = IP(src=src_ipv4_addr, dst=dst_ipv4_addr, proto=6, ttl=255)
# dport=179 means, we are communicating with bgp port of the destination router/ host. sport is a random port over which tcp is established. seq and ack are the sequence number and acknowledgement numbers. flags = PA are the PUSH and ACK flags.
tcp = TCP(sport=established_port, dport=179,
          seq=current_seq_num, ack=expected_seq_num, flags='PA')
# type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication. max hex int (all f) are used for no auth.
hdr = BGPHeader(type=bgp_type, marker=0xffffffffffffffffffffffffffffffff)
# update packet consist of path attributes and NLRI (Network layer reachability information),  type_code in path attributes is for which type of path attribute it is. [more][3]
up = BGPUpdate(
    withdrawn_routes=[
        BGPNLRI_IPv4(prefix=NLRI_PREFIX_WITHDRAWN1),
        BGPNLRI_IPv4(prefix=NLRI_PREFIX_WITHDRAWN2)
    ],
    path_attr=[
        # ORIGIN: IGP
        # Transitive well-known compelete \x40; ORIGIN: IGP \x01; Length: 1 \x01; originator is IGP
        BGPPathAttr(type_flags=0x40, type_code=1, attribute=b'\x00'),
        # AS_PATH: 1 2 3; Transitive Extended-Length well-known compelete \x50
        # segment type: AS_SEQUENCE \x02; Length: 3 \x03; AS: 1 2 3
        BGPPathAttr(type_flags=0x50, type_code=2,
                    attribute=b'\x02\x03' + b'\x00\x00\x00\x01' + b'\x00\x00\x00\x02' + b'\x00\x00\x00\x03'),
        # NEXT_HOP: local
        BGPPathAttr(type_flags=0x40, type_code=3,
                    # src_ip:转成16进制，四个字节，每个字节两位，前面补0
                    attribute=src_ipv4_addr_byte),
        # MULTI_EXIT_DISC: 0
        BGPPathAttr(type_flags=0x80, type_code=4,
                    attribute=b"\x00\x00\x00\x00"),
        # COMMUNITIES: 123:456 321:654
        BGPPathAttr(type_flags=0xc0, type_code=8,
                    attribute=b'\x00\x7b' + b'\x01\xc8' +
                    b'\x01\x41' + b'\x02\x8e'),
    ], nlri=[
        BGPNLRI_IPv4(prefix=NLRI_PREFIX1),
        BGPNLRI_IPv4(prefix=NLRI_PREFIX2)
    ])

packet = base / tcp / hdr / up

send(packet, iface='VMware Network Adapter VMnet8')
