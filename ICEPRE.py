import binascii
import csv
import os
import time
import argparse
import yaml
import angr

import evaluation.syntax_evaluation
from Ctracer import CTracer
from InferSyntax import infer_field

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from memory_profiler import profile

import logging
logging.getLogger('angr').setLevel('ERROR')


def merge_trace(inferred_boundary, offset_set):
    field_sum = inferred_boundary.count(True) + 1
    field_id = 0
    filed_trace = {}
    for i in range(len(inferred_boundary) + 1):

        # for key, trace_set in offset_set.item():
        if i in offset_set:
            if field_id in filed_trace:
                filed_trace[field_id] = filed_trace[field_id].union(offset_set[i])
            else:
                filed_trace[field_id] = offset_set[i]

        if i == len(inferred_boundary):
            break

        if i <= len(inferred_boundary) and inferred_boundary[i]:
            field_id += 1
    return filed_trace


def single_infer(protocol_name, binary_p, library_dir, traffic, hook_options):
    modbus_ct = CTracer(protocol_name, binary_p, library_dir, traffic,
                        hooked_symbol=hook_options['hook_s'], hooked_addr=hook_options['hook_addr'],
                        end_symbol=hook_options['end_s'], end_addr=hook_options['end_addr'])

    # modbus_ct.calc_state_num()
    track_results = modbus_ct.concolic_analyze()
    start_state = modbus_ct.get_start_state()

    if track_results == {}:
        print('message is abnormal')
        return
    # print(track_results)
    infer_field_boundary, offset_set_dic = infer_field(track_results, len(traffic))

    exec_info = modbus_ct.get_summary()
    # modbus_ct.calc_state_num()


def multi_infer(protocol_name, binary_p, library_dir, pcap_file, hook_options, num_limit, results_file):
    """
    Infer the protocol from multiple messages in a pcap file.

    Parameters
    ----------
    protocol_name : str
        The name of the protocol to infer.
    binary_p : str
        The path of the binary that implements the protocol.
    library_dir : str
        The path of the library directory.
    pcap_file : str
        The path of the pcap file that contains the messages to infer.
    hook_options : dict
        The options of the hook.
    num_limit : int
        The maximum number of messages to infer.
    results_file : str
        The path of the file to store the results.

    Returns
    -------
    None
    """
    results = []
    # Generate ground truth
    messages_groundtruth = evaluation.syntax_evaluation.get_groundtruth(pcap_file)

    # start inferring
    # Metrics
    y_true = []
    y_pred = []

    true_field_num = 0
    perfection_field_num = 0

    sum_of_state_num = 0

    num = 1
    start_state = None
    for traffic_data_item, msg_gt in messages_groundtruth.items():
        if num > num_limit:
            break
        print('{}th message'.format(num))
        print(traffic_data_item)
        print(msg_gt)
        modbus_ct = CTracer(protocol_name, binary_p, library_dir, traffic_data_item, start_state=start_state,
                            hooked_symbol=hook_options['hook_s'], hooked_addr=hook_options['hook_addr'],
                            end_symbol=hook_options['end_s'], end_addr=hook_options['end_addr'])

        # modbus_ct.update_traffic(traffic_data_item)
        track_results = modbus_ct.concolic_analyze()
        start_state = modbus_ct.get_start_state()

        if track_results == {}:
            print('{}th message is abnormal'.format(num))
            results.append([num, binascii.b2a_hex(traffic_data_item), msg_gt, 'abnormal'])
            num += 1
            continue
        # print(track_results)
        infer_field_boundary, offset_set_dic = infer_field(track_results, len(traffic_data_item))

        results.append([num, binascii.b2a_hex(traffic_data_item), msg_gt, infer_field_boundary])

        # field_trace = merge_trace(infer_field_boundary, offset_set_dic)
        # print(field_trace)
        exec_info = modbus_ct.get_summary()
        sum_of_state_num += exec_info['s_State_Num']
        sum_of_state_num += exec_info['c_State_Num']

        tf, pf = evaluation.syntax_evaluation.perfection_count(infer_field_boundary, msg_gt)
        true_field_num += tf
        perfection_field_num += pf

        # print(infer_field_boundary[:46])
        # print(msg_gt[:46])
        y_pred += infer_field_boundary
        y_true += msg_gt

        num += 1

    # evaluation
    # print('-' * 15, f'Evaluation(dataset size={num-1})', '-' * 15)
    # print('---------State Results---------')
    # print('Num of states:')
    # print(sum_of_state_num)

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    confusion = confusion_matrix(y_true, y_pred)

    perfection = perfection_field_num / true_field_num

    with open(results_file, 'w') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["No.", "Raw Data", "Ground Truth", "Inference Result"])  # header row
        writer.writerows(results)
        writer.writerow([])
        writer.writerow(["Accuracy", "Precision", "Recall", "F1 Score", "Perfection"])  # metric header row
        writer.writerow([accuracy, precision, recall, f1, perfection])


def show_all_objects(binary_file, library_path):
    proj = None
    if library_path:
        proj = angr.Project(binary_file, ld_path=library_path)
    else:
        proj = angr.Project(binary_file)

    print(proj.loader.all_objects)


def main():
    parser = argparse.ArgumentParser(description='ICEPRE')
    parser.add_argument('-p', '--protocol', required=True, help='Protocol name')
    parser.add_argument('-c', '--config', required=True, help='Path to configuration file')
    parser.add_argument('-b', '--batch', action='store_true', help='Batch mode')
    batch_group = parser.add_argument_group('Batch mode options')
    batch_group.add_argument('-f', '--pcap_file', help='PCAP file path (required in batch mode)')
    batch_group.add_argument('-n', '--num_messages', type=int, help='Number of messages (required in batch mode)')
    parser.add_argument('-d', '--hex_data', help='Hexadecimal data string (required in non-batch mode)')

    args = parser.parse_args()

    with open(args.config, 'r') as f:
        config = yaml.safe_load(f)

    hook_option = config['hook_option']
    print('Protocol: ' + args.protocol)
    print('Config_file: ' + args.config)

    # Call the multi_infer function with the parsed arguments
    if args.batch:
        print('Batch mode enabled\n')
        csv_file_name = f"results/{args.protocol}_{args.num_messages}_messages.csv"

        # Create the results directory if it doesn't exist
        if not os.path.exists("results"):
            os.makedirs("results")
        multi_infer(args.protocol, config['binary_p'], config['library_dir'], args.pcap_file, hook_option, args.num_messages, csv_file_name)
        print(f"Saving results to {csv_file_name}")
    else:
        print('Message: ' + args.hex_data)
        single_infer(args.protocol, config['binary_p'], config['library_dir'], binascii.a2b_hex(args.hex_data), hook_option)


if __name__ == "__main__":
    main()  # modbus iec104 s7comm ENIP
