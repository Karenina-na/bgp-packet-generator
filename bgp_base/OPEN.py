from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPOptParam
from scapy.sendrecv import send
import struct

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
bgp_type = 1
src_ipv4_addr = '192.168.80.1'  # eth0
dst_ipv4_addr = '192.168.80.254'
established_port = 12345  # random port
current_seq_num = 1500  # seq
expected_seq_num = 1000  # ack
my_asn = 23456
bgp_id = '192.168.80.1'  # router id

# proto=6 represents that, TCP will be travelling above this layer. This is simple IPV4 communication.
base = IP(src=src_ipv4_addr, dst=dst_ipv4_addr, proto=6, ttl=255)
# dport=179 means, we are communicating with bgp port of the destination router/ host. sport is a random port over which tcp is established. seq and ack are the sequence number and acknowledgement numbers. flags = PA are the PUSH and ACK flags.
tcp = TCP(sport=established_port, dport=179,
          seq=current_seq_num, ack=expected_seq_num, flags='PA')
# type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication. max hex int (all f) are used for no auth.

hdr = BGPHeader(type=bgp_type, marker=0xffffffffffffffffffffffffffffffff)

up = BGPOpen(version=4, my_as=my_asn, hold_time=180, bgp_id=bgp_id,
             opt_params=[
                 # Multiprotocol Extensions for BGP-4(RFC) 1
                 BGPOptParam(
                     param_type=2, param_value=b'\x01\x04\x00\x01\x00\x01'),
                 # route refresh capability(RFC) Cisco 128
                 BGPOptParam(param_type=2, param_value=b'\x80\x00'),
                 # route refresh capability(RFC) 2
                 BGPOptParam(param_type=2, param_value=b'\x02\x00'),
                 # enhanced route refresh capability(RFC) 70
                 BGPOptParam(param_type=2, param_value=b'\x46\x00'),
                 # support for 4-octet AS number capability(RFC) 65 \x41\x04+ASN
                 BGPOptParam(param_type=2, param_value=bytes(
                     [65, 4]) + struct.pack("!L", my_asn)),
                 # bgp extended message(RFC) 6
                 BGPOptParam(param_type=2, param_value=b'\x06\x00'),
                 # support for additional paths capability(RFC) 69
                 # FQDN capability(RFC) 73， hostname=ubuntu01 \x75\x62\x75\x6e\x74\x75\x30\x31
                 BGPOptParam(
                     param_type=2, param_value=b'\x49\x0a\x08\x75\x62\x75\x6e\x74\x75\x30\x31\x00'),
             ])

packet = base / tcp / hdr / up

send(packet, iface='VMware Network Adapter VMnet8')
