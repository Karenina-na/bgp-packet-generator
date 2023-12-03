import socket
from scapy.layers.inet import IP, TCP
from scapy.contrib.bgp import BGPHeader, BGPOpen, BGPOptParam
from scapy.sendrecv import send
import struct
import time


def create_open_message(my_asn, bgp_id):

    # BGP header is created with the required fields.
    hdr = BGPHeader(type=1, marker=0xffffffffffffffffffffffffffffffff)

    up = BGPOpen(version=4, my_as=my_asn, hold_time=180, bgp_id=bgp_id,
                 opt_params=[
                     #  # Multiprotocol Extensions for BGP-4(RFC) 1
                     #  BGPOptParam(
                     #      param_type=2, param_value=b'\x01\x04\x00\x01\x00\x01'),
                     #  # route refresh capability(RFC) Cisco 128
                     #  BGPOptParam(param_type=2, param_value=b'\x80\x00'),
                     #  # route refresh capability(RFC) 2
                     #  BGPOptParam(param_type=2, param_value=b'\x02\x00'),
                     #  # enhanced route refresh capability(RFC) 70
                     #  BGPOptParam(param_type=2, param_value=b'\x46\x00'),
                     #  # support for 4-octet AS number capability(RFC) 65 \x41\x04+ASN
                     #  BGPOptParam(param_type=2, param_value=bytes(
                     #      [65, 4]) + struct.pack("!L", my_asn)),
                     #  # bgp extended message(RFC) 6
                     #  BGPOptParam(param_type=2, param_value=b'\x06\x00'),
                     #  # support for additional paths capability(RFC) 69
                     #  # FQDN capability(RFC) 73， hostname=ubuntu01 \x75\x62\x75\x6e\x74\x75\x30\x31
                     #  BGPOptParam(
                     #      param_type=2, param_value=b'\x49\x0a\x08\x75\x62\x75\x6e\x74\x75\x30\x31\x00'),
                 ])

    packet = hdr / up
    return packet


def create_keepalive_message():
    hdr = BGPHeader(type=4, marker=0xffffffffffffffffffffffffffffffff)
    packet = hdr
    return packet


if __name__ == "__main__":
    src_ipv4_addr = '192.168.80.1'
    dst_ipv4_addr = '192.168.80.35'
    my_asn = 200
    bgp_id = src_ipv4_addr
    sk = socket.socket()
    sk.connect((dst_ipv4_addr, 179))

    # send open message
    packet = create_open_message(my_asn, bgp_id)
    sk.send(packet.build())

    # receive open message
    data = sk.recv(4096)

    # resolve open message
    tamplate = BGPHeader(data)
    print(tamplate.show())

    # send keepalive message
    packet = create_keepalive_message()
    sk.send(packet.build())

    # receive keepalive message
    data = sk.recv(4096)
    tamplate = BGPHeader(data)
    print(tamplate.show())

    # send keepalive message
    packet = create_keepalive_message()
    sk.send(packet.build())

    # tcp end
    sk.close()
