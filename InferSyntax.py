import json
import os

from thefuzz import fuzz
from thefuzz import process
import re
import copy

# # dir_path = 'result/iec61850-mms/taint-trace-async'
# dir_path = 'result/modbus/taint-trace-random'

threshold = 99
insLen_threshold = 20


def calculate_similarity(str1, str2):
    similarity = fuzz.ratio(str1, str2)
    return similarity


def divide_field(traces, field_boundary):
    for offset in sorted(traces):
        if offset - 1 in traces:
            similarity_ratio = calculate_similarity(traces[offset-1], traces[offset])
            # print(offset - 1, "and", offset, "ratio: ", similarity_ratio)

            if similarity_ratio >= threshold:
                field_boundary[offset-1] = 0
    # merge unused bytes
    for i in range(len(field_boundary)+1):
        if i in traces or (i - 1) in traces:
            continue
        field_boundary[i - 1] = 0

    return field_boundary


def revise(field_boundary, field_ass):
    """
    Merge fields based on field associations.
    Note: Field associations can cause fields to be over-merged
    """
    for association_range in field_ass:
        start, end = association_range
        # set boundary
        if start > 0:
            field_boundary[start-1] = 1
        for i in range(start, end-1):
            field_boundary[i] = 0
        if end - 1 < len(field_boundary):
            field_boundary[end-1] = 1
    return field_boundary


def format_display(boundary, data_len):
    format_str = ''
    for i in range(data_len):
        format_str += str(i)
        format_str += ' '
        if i < data_len - 1 and boundary[i]:
            format_str += '| '
    print('Inferred results:')
    print(format_str)


def infer_field(trace_dic, data_len):
    field_boundary = [1] * (data_len - 1)
    # ins_set_dic_lst: { offset1: str(bb1_addr+bb2_addr...)], offset2:str()...}
    ins_set_dic = {}
    # ins_set_dic_lst: { offset1: [bb1_addr, bb2...], offset2:[]...}
    ins_set_dic_lst = {}
    field_association = []
    for tag, trace in trace_dic.items():
        start_offset, end_offset = tag
        bytes_num = end_offset - start_offset

        if bytes_num == 1:
            ins_list = [item['addr'] for item in trace]
            ins_set_dic_lst[start_offset] = set(ins_list)

            ins_set = ' '.join(map(str, ins_list))
            # ins_set = ' '.join(map(str, trace))
            ins_set_dic[start_offset] = ins_set
        else:
            field_association.append(tag)

            # Extract the trace set of each offset byte
            ins_list = [item['addr'] for item in trace]
            for i in range(start_offset, end_offset):
                if i in ins_set_dic_lst:
                    ins_set_dic_lst[i] = ins_set_dic_lst[i].union(set(ins_list))
                else:
                    ins_set_dic_lst[i] = set(ins_list)

    infer_boundary = divide_field(ins_set_dic, field_boundary)
    # print("divide results: ", field_list)
    # print("association field:", field_association)

    revised_boundary = revise(infer_boundary, field_association)

    format_display(revised_boundary, data_len)

    return revised_boundary, ins_set_dic_lst

    # field_result_path = f'result/iec61850-mms/inferred-fields.txt'
    # with open(field_result_path, 'w') as json_file:
    #     print(field_list, file=json_file)


def main():
    trace_res = {}
    len_s = 12
    infer_field(trace_res, len_s)


if __name__ == "__main__":
    main()
