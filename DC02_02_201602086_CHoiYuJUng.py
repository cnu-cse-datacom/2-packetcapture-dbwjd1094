import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s",data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:",ether_src)
    print("dest_mac_address:",ether_dest)
    print("ip_version",ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
       ethernet_addr.append(i.hex())   
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr

def parsing_ip_header(data):
    ip_header = struct.unpack("!1s1s2s2s2s1c1c2s4c4c",data)
    ip_version = int(ip_header[0].hex(),16) >> 4
    ip_length = int(ip_header[0].hex()[1],16)
    dsc = int(ip_header[1].hex(),16) >> 4
    ecn = int(ip_header[1].hex()[1],16)
    tl = int(ip_header[2].hex(),16)
    identification = int(ip_header[3].hex(),16)
    flags = int(ip_header[4].hex(),16)
    rb = int(ip_header[4].hex()[0],16)
    nf = int(ip_header[4].hex()[1],16)
    fragments = int(ip_header[4].hex()[2],16)
    fragments_offset = int(ip_header[4].hex()[3],16)
    Ttl = int(ip_header[5].hex(),16)
    protocol = int(ip_header[6].hex(),16)
    hc = "0x"+ip_header[7].hex()
    source_ip_address = convert_ip_address(ip_header[8:12])
    dest_ip_address = convert_ip_address(ip_header[12:16])

    print("=========ip_header=========")
    print("ip_version: ",ip_version)
    print("ip_Length: ",ip_length)
    print("differentiated_service_codepoint: ",dsc)
    print("explicit_congest_notification: ",ecn)
    print("total_length: ",tl)
    print("identification: ",identification)
    print("flags: ",flags)
    print(">>>reserved_bit: ",rb)
    print(">>>not_fragments: ",nf)
    print(">>>fragments: ",fragments)
    print(">>>fragments_offset: ",fragments_offset)
    print("Time to live: ",Ttl)
    print("protocol: ",protocol)
    print("header checksum: ",hc)
    print("source_ip_address: ",source_ip_address)
    print("dest_ip_address: ",dest_ip_address)
    return protocol
    
def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(i.hex())
    ip_addr = ":".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!1c1c2s2s2s4s4s4s",data)
    sp = int(tcp_header[0].hex(),16)
    dp = int(tcp_header[1].hex(),16)
    sn = int(tcp_header[2].hex(),16)
    an = int(tcp_header[3].hex(),16)
    four_h = tcp_header[4].hex()
    hl = int(four_h,16) >> 4
    flags = int(four_h[1:4],16)
    reserved = int(four_h,16) & 15
    nonce = int(four_h,16) & 128
    cwr = int(four_h,16) & 64
    urgent = int(four_h,16) & 32
    ack = int(four_h,16) & 16
    push = int (four_h,16) & 8
    reset = int(four_h,16) & 4
    syn = int(four_h,16) & 2
    fin = int(four_h,16) & 1
    wsv = int(tcp_header[5].hex(),16)
    cs = int(tcp_header[6].hex(),16)
    up = int(tcp_header[7].hex(),16)

    print("=========tcp_header=========")
    print("src_port: ",sp)
    print("dec_port: ",dp)
    print("seq_num: ",sn)
    print("ack_num: ",an)
    print("header_len: ",hl)
    print("flags: ",flags)
    print(">>>reserved: ",reserved)
    print(">>>nonce: ",nonce)
    print(">>>>cwr: ",cwr)
    print(">>>urgent: ",urgent)
    print(">>>ack: ",ack)
    print(">>>push: ",push)
    print(">>>reset: ",reset)
    print(">>>syn: ",syn)
    print(">>>fin: ",fin)
    print("window_size_value: ",wsv)
    print("checksum: ",cs)
    print("urgent_pointer: ",up)


def parsing_udp_header(data):
    udp_header = struct.unpack("!2s2s2s2s",data)
    sp = int(udp_header[0].hex(),16)
    dp = int(udp_header[1].hex(),16)
    leng = int(udp_header[2].hex(),16)
    hc = int(udp_header[3].hex(),16)

    print("=========udp_header=========")
    print("src_port: ",sp)
    print("dst_port: ",dp)
    print("leng: ",leng)
    print("header checksum: ",hc)


recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
    data = recv_socket.recvfrom(20000)
    parsing_ethernet_header(data[0][0:14])
    proto = parsing_ip_header(data[0][14:34])
    if(proto == 17):
        parsing_udp_header(data[0][34:42])
    elif(proto == 6):
        parsing_tcp_header(data[0][34:54])
