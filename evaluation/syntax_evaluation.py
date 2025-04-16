"""
Parse a PCAP file and print its dissection.
This script primarily is intended to check whether the dissection of a specific PCAP works and all fields can be
interpreted correctly to create a baseline to compare inferences to.
"""

import time
from argparse import ArgumentParser
from os.path import isfile
from sys import exit

from netzob.Model.Vocabulary.Messages.RawMessage import RawMessage

# import IPython

from evaluation.nemesysUtils.messageParser import ParsedMessage
from evaluation.nemesysUtils.loader import SpecimenLoader

# logging.basicConfig(level=logging.DEBUG)
# logging.getLogger().setLevel(logging.DEBUG)


def get_groundtruth(pcapfile, target_layer=None, relative_to_ip=None):
    if not isfile(pcapfile):
        print('File not found: ' + pcapfile)
        exit(1)

    specimens = SpecimenLoader(pcapfile)
    print('Loaded PCAP file:', specimens.pcapFileName)
    # pkt = list(specimens.messagePool.values())

    st = time.time()

    pms = ParsedMessage.parseOneshot(specimens)
    pms_l = list(pms.values())
    msgs_boundary_groundtruth = {}

    # print("Dissection ran in {:3.2f} seconds.".format(time.time() - st))
    for msg, pm in pms.items():  # type: RawMessage, ParsedMessage
        # pm.printUnknownTypes()
        # pm.getFieldNames()
        boundary_gt = pm.generate_groundtruth()
        msgs_boundary_groundtruth[msg.data[-pm.tcp_payload_len:]] = boundary_gt
        # print(msg.data[-pm.tcp_payload_len:])
        # print(boundary_gt)

    print('total num: {}'.format(len(msgs_boundary_groundtruth.keys())))
    # print('messages\' boundaries:')
    # print(msgs_boundary_groundtruth)

    ParsedMessage.closetshark()

    print('Loaded PCAP in: specimens')

    return msgs_boundary_groundtruth


def perfection_count(inferred_boundary, true_boundary):
    true_field_num = true_boundary.count(1) + 1
    LEN = len(inferred_boundary)
    perfection_num = 0
    start_index = 0
    for i in range(LEN):
        if inferred_boundary[i]:
            if inferred_boundary[start_index:i+1] == true_boundary[start_index:i+1]:
                perfection_num += 1
            start_index = i
        # elif i == len(inferred_boundary)-1:
        #     if inferred_boundary[start_index:i+1] == true_boundary[start_index:i+1]:
        #         perfection_num += 1
        # if start_index == len(inferred_boundary)-1 and true_boundary[start_index]:
        #     perfection_num += 1
    if inferred_boundary[start_index:LEN] == true_boundary[start_index:LEN]:
        perfection_num += 1
    # print(perfection_num)
    # print(true_field_num)
    return true_field_num, perfection_num


def main():
    pcapfilename = '/home/qybpt/Desktop/ConcolicTrace/traffic/modbus/specified_modbus.pcapng'

    messages_gt = get_groundtruth(pcapfilename)


if __name__ == '__main__':
    # parser = ArgumentParser(
    #     description='Dissect PCAP with tshark and parse to python.')
    # parser.add_argument('pcapfilename', help='pcapfilename')
    # parser.add_argument('-l', '--targetlayer', type=int)
    # parser.add_argument('-r', '--relativeToIP', default=False, action='store_true')
    # args = parser.parse_args()
    #
    # get_groundtruth(args.pcapfilename)

    main()
