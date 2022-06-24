import sys
import dpkt
from collections import namedtuple
from collections import deque
import struct
import tracemalloc

pcap_file = sys.argv[1]

tracemalloc.start()
fin = open(pcap_file, 'rb')
pcap = dpkt.pcap.Reader(fin)
raw_data = []
fout = open('result.raw', 'bw')

for ts, packet in pcap:
    eth = dpkt.ethernet.Ethernet(packet)
    ip = eth.data
    tcp = ip.data

fout.close()
print("Current: %d, Peak %d" % tracemalloc.get_traced_memory())
