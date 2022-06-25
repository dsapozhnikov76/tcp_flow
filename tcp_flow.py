import sys
import time
import pypacker.layer12.ethernet as pyeth
import pypacker.layer3.ip as pyip
import pypacker.layer4.tcp as pytcp

from pypacker import ppcap
import tracemalloc

pcap_file = sys.argv[1]


def get_flags(l_flags):
    urg = l_flags & 0x020
    urg >>= 5
    ack = l_flags & 0x010
    ack >>= 4
    psh = l_flags & 0x008
    psh >>= 3
    rst = l_flags & 0x004
    rst >>= 2
    syn = l_flags & 0x002
    syn >>= 1
    fin = l_flags & 0x001
    fin >>= 0
    return list(filter(''.__ne__, ['URG' if urg else '',
                                   'ACK' if ack else '',
                                   'PSH' if psh else '',
                                   'RST' if rst else '',
                                   'SYN' if syn else '',
                                   'FIN' if fin else ''
                                   ]))


tracemalloc.start()

pcap = ppcap.Reader(pcap_file)
raw_data = []

STREAMS = dict()

for p in pcap:
    ts, packet = p
    eth = pyeth.Ethernet(packet)
    ip = pyip.IP(eth.body_bytes)
    if ip.p_t == 'IP_PROTO_TCP':
        tcp = pytcp.TCP(ip.body_bytes)
        hash_src = hash(ip.src_s) + hash(tcp.sport)
        hash_dst = hash(ip.dst_s) + hash(tcp.dport)
        hashsum = hash_src + hash_dst
        flags = get_flags(tcp.flags)
        a = [ip.src_s, tcp.sport, ip.dst_s, tcp.dport, tcp.seq, tcp.flags, flags, len(tcp.body_bytes)]
        if hashsum in STREAMS:
            if hash_src in STREAMS[hashsum]:
                STREAMS[hashsum][hash_src].append(a)
            else:
                STREAMS[hashsum][hash_src] = [a]
        else:
            STREAMS[hashsum] = dict()
            STREAMS[hashsum][hash_src] = [a]

stream_id = 0
for stream in STREAMS.keys():
    side_id = 0
    for side in STREAMS[stream].keys():
        side_flags = []
        for pack in range(len(STREAMS[stream][side])):
            side_flags.extend(STREAMS[stream][side][pack][6])
        print('Stream: ', stream_id, ' side ', side_id, end='')
        print(' Uniq flags: ', list(dict.fromkeys(side_flags)))
        side_id += 1
    stream_id += 1


print("Current: %d, Peak %d" % tracemalloc.get_traced_memory())
