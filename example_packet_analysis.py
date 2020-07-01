'''
This file analyses a pcap file to determine which data sources are best

Input
 - sample_feed.pcap
Output
 - graph and metrics of total delay time from each UDP source
'''

import os
import sys
import matplotlib.pyplot as plt
import numpy as np
from scapy.all import rdpcap
from scapy.layers.inet import IP


class Packet():
    def __init__(self, source, delay):
        self.publisher = source
        self.delaytime = delay


class AnalysePcap():
    def __init__(self, filename):
        self.filename = filename
        self.data = {}

        if not os.path.isfile(filename):
            print('"{}" does not exist'.format(filename), file=sys.stderr)
            sys.exit(-1)

    def read(self):
        print('Reading {}...'.format(self.filename))
        packets = rdpcap(self.filename)

        count = 0
        for packet in packets:
            price_data = packet.load
            publisher = IP(packet).id

            if price_data not in self.data.keys():
                self.data[price_data] = [Packet(publisher, 0)]
                starttime = packet.time
            else:
                self.data[price_data].append(
                    Packet(publisher, packet.time - starttime))

            count += 1
        print(count, 'packets processed.\n')

    def preview_data_structure(self):
        for x in (list(self.data))[:3]:
            print('{}: {}'.format(x, self.data[x]))
        for x in (list(self.data))[-3:]:
            print('{}: {}'.format(x, self.data[x]))

    def output_summary(self):

        # first entry of sum_delays is not used, so that source ID == index
        sum_delays = [-1, 0, 0, 0, 0]
        count_arrivals = [-1, 0, 0, 0, 0]
        for seqno_arrivals in self.data.values():
            for arrival in seqno_arrivals:
                sum_delays[arrival.publisher] += arrival.delaytime
                count_arrivals[arrival.publisher] += 1

        print('Total delays of sources [1, 2, 3, 4]:')
        print(['%.1f seconds' % source_delay for source_delay in sum_delays[1:]])
        print('Total number of arrivals from [1, 2, 3, 4]: ')
        print(count_arrivals[1:])
        print('Source 2 is missing 11 packets!\n')

    def output_graph(self):
        count_first_arrivals = [-1, 0, 0, 0, 0]
        for seqno_arrivals in self.data.values():
            publisher = seqno_arrivals[0].publisher
            count_first_arrivals[publisher] += 1

        sources = [1, 2, 3, 4]
        index = np.arange(4)
        plt.bar(index, count_first_arrivals[1:])
        plt.xlabel('Source')
        plt.ylabel('No of "first" arrivals')
        plt.xticks(index, sources)
        xlocs, _ = plt.xticks()
        for i, v in enumerate(count_first_arrivals[1:]):
            plt.text(xlocs[i], v, str(v))

        plt.title('Number of "first" arrivals for each UDP source')
        plt.show()


if __name__ == '__main__':

    filename = 'sample_feed.pcap'

    myPcap = AnalysePcap(filename)

    myPcap.read()
    # myPcap.preview_data_structure()

    myPcap.output_summary()

    myPcap.output_graph()
