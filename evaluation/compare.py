from evaluation import syntax_evaluation
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from evaluation.nemesysUtils.loader import SpecimenLoader
from evaluation.nemesysUtils.messageParser import ParsedMessage

netzob_modbus_results = [1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,1,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0]
netzob_base = [1, 1, 0, 0, 1]

def nemesys_cal_metric(p_name, pcap):
    df = pd.read_csv('/home/qybpt/Desktop/ConcolicTrace/result/comparedToolsResult/{}_results.csv'.format(p_name),
                     usecols=[1])
    y_ = df.values.tolist()
    print(y_)

    # start inferring
    # Metrics
    y_true = []
    y_pred = []
    for i in y_:
        y_pred.append(i[0])

    true_field_num = 0
    perfection_field_num = 0
    start_p = 0

    specimens = SpecimenLoader(pcap)
    print('Loaded PCAP file:', specimens.pcapFileName)
    # pkt = list(specimens.messagePool.values())

    pms = ParsedMessage.parseOneshot(specimens)
    pms_l = list(pms.values())
    msgs_boundary_groundtruth = {}

    # print("Dissection ran in {:3.2f} seconds.".format(time.time() - st))
    for msg, pm in pms.items():  # type: RawMessage, ParsedMessage
        print(msg.data[-pm.tcp_payload_len:])
        # pm.getFieldNames()
        boundary_gt = pm.generate_groundtruth()
        y_true += boundary_gt
        l = len(boundary_gt)

        print(boundary_gt)
        print(y_pred[start_p:start_p + l])

        tf, pf = syntax_evaluation.perfection_count(y_pred[start_p:start_p + l], boundary_gt)
        true_field_num += tf
        perfection_field_num += pf

        start_p += l

    ParsedMessage.closetshark()

    print(len(y_true))
    print(len(y_pred))

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    confusion = confusion_matrix(y_true, y_pred)
    print('#########{}##########'.format(p_name))
    print('---------Boundary Results---------')
    print('len of y_true: {}'.format(len(y_true)))
    print('len of y_pred: {}'.format(len(y_pred)))
    print("Accuracy: ", accuracy)
    print("Precision: ", precision)
    print("Recall: ", recall)
    print("F1 Score: ", f1)
    print("Confusion Matrix: ")
    print(confusion)

    print('---------Perfection Results---------')
    perfection = perfection_field_num / true_field_num
    print('perfection: {}'.format(perfection))


def cal_metric(p_name, pcap):

    # start inferring
    # Metrics
    y_true = []
    y_pred = []

    true_field_num = 0
    perfection_field_num = 0

    specimens = SpecimenLoader(pcap)
    print('Loaded PCAP file:', specimens.pcapFileName)
    # pkt = list(specimens.messagePool.values())

    pms = ParsedMessage.parseOneshot(specimens)
    pms_l = list(pms.values())
    msgs_boundary_groundtruth = {}

    # print("Dissection ran in {:3.2f} seconds.".format(time.time() - st))
    for msg, pm in pms.items():  # type: RawMessage, ParsedMessage
        print(msg.data[-pm.tcp_payload_len:])
        # pm.getFieldNames()
        boundary_gt = pm.generate_groundtruth()
        boundary_infer = [1, 1, 0, 0, 1]
        y_true += boundary_gt
        l = len(boundary_gt)
        boundary_infer += [0]*(l-5)
        y_pred+=boundary_infer

        print(boundary_gt)
        print(boundary_infer)

        tf, pf = syntax_evaluation.perfection_count(boundary_infer, boundary_gt)
        true_field_num += tf
        perfection_field_num += pf


    ParsedMessage.closetshark()


    # for traffic_data_item, msg_gt in messages_groundtruth.items():
    #     y_true += msg_gt
    #     l = len(msg_gt)
    #
    #     print(msg_gt)
    #     print(y_pred[start_p:start_p+l])
    #
    #     tf, pf = syntax_evaluation.perfection_count(y_pred[start_p:start_p+l], msg_gt)
    #     true_field_num += tf
    #     perfection_field_num += pf
    #
    #     start_p+=l

    print(len(y_true))
    print(len(y_pred))

    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred)
    recall = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    confusion = confusion_matrix(y_true, y_pred)
    print('#########{}##########'.format(p_name))
    print('---------Boundary Results---------')
    print('len of y_true: {}'.format(len(y_true)))
    print('len of y_pred: {}'.format(len(y_pred)))
    print("Accuracy: ", accuracy)
    print("Precision: ", precision)
    print("Recall: ", recall)
    print("F1 Score: ", f1)
    print("Confusion Matrix: ")
    print(confusion)

    print('---------Perfection Results---------')
    perfection = perfection_field_num / true_field_num
    print('perfection: {}'.format(perfection))


if __name__ == "__main__":
    md_p='/home/qybpt/Desktop/ConcolicTrace/traffic/modbus/specified_modbus56.pcapng'
    s7_pcap = '/home/qybpt/Desktop/ConcolicTrace/traffic/s7comm/specified.pcapng'
    iec104_pcap = '/home/qybpt/Desktop/ConcolicTrace/traffic/iec104/100messages.pcap'
    enip_pcap = '/home/qybpt/Desktop/ConcolicTrace/traffic/ENIP/100message.pcap'
    cal_metric('modbus', md_p)