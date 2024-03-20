import argparse
import csv
import json
import joblib
import pandas as pd
import numpy as np
import datetime
from collections import deque
from sklearn.metrics import confusion_matrix
from sklearn import metrics
import matplotlib.pyplot as plt
import seaborn as sns

global THRESHOLD


def parse_configuration():
    with open("../config.json", "r") as f:
        config = json.load(f)
        global ABSOLOUTEPATH, FILE_PATH, INTERVALS, START_TIME, UDP_THRESHOLD, PRIMARY_DOMAIN, CLOUD_DOMAINS, TIME_INTERVAL
        global LABELS, PATH
        try:
            TIME_INTERVAL = 10
            PATH = config["outputPath"]
            ABSOLOUTEPATH = config["outputPath"]
            FILE_PATH = "../dataFormat/"
            PRIMARY_DOMAIN = config["primaryDomains"]
            CLOUD_DOMAINS = config["cloudDomains"]
            INTERVALS = config["Metaverses"]["Multiverse2"]["intervals"]
            LABELS = [x for x in INTERVALS]
        except Exception as e:
            print(e)


def parse_models(time, model):
    path = PATH + model + "/"
    statelessPacket = joblib.load(
        f"{path}random_forrest_Meta_Operated_Packet_Attributes_{time}.joblib"
    )
    statelessBoth = joblib.load(
        f"{path}random_forrest_MetaOperated_Attributes_Packet_and_Flow_{time}.joblib"
    )

    return statelessPacket, statelessBoth


def parse_file(file):
    contents = []
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for row in csv_reader:
            contents.append(row)
    return contents


def format_data(data):
    # Load dataset
    dataMap = {}
    dataSet = np.array(data)
    headers = dataSet[0][4:]
    activity = dataSet[:, 3][2:]
    dataMap["activity"] = activity
    for x in range(len(headers)):
        label = headers[x]
        dataMap[label] = dataSet[:, x + 4][2:]

    dataFrame = pd.DataFrame(dataMap)
    return dataFrame, headers


def read_attributes():
    metaOperated = parse_file(f"{FILE_PATH}Buffered-Packet-Flow.csv")
    metaPacket = parse_file(f"{FILE_PATH}Buffered-Packet.csv")
    return metaOperated, metaPacket


def convertLabelToNumber(label):
    for x in range(len(LABELS)):
        if label == LABELS[x]:
            return x

    print("Could not fine label " + str(label))

    return label


def test_model(state, stateless, testSet):
    correctStates = []
    predictedStates = []
    inferenceTime = []
    total_accuarcy = []
    allData = []
    # Right most state is the most recent
    localStates = deque()
    startTime = int(testSet[2][1])
    # Initial setup stage
    for i in range(state):
        pred = stateless.predict([testSet[i + 2][4:]])
        localStates.append(pred[0])
        predictedStates.append(pred[0])
        correctStates.append(testSet[i + 2][3])

        stateless_accuarcy = stateless.predict_proba([testSet[i + 2][4:]])
        stateless_accuarcy = max(stateless_accuarcy[0])
        currTime = int(testSet[i + 2][1]) - startTime
        allData.append((pred[0], testSet[i + 2][3], stateless_accuarcy, currTime))

    # Processing data stage
    for i in range(state + 2, len(testSet)):
        t1 = datetime.datetime.now()
        dataLine = testSet[i][4:]
        for x in localStates:
            dataLine.append(convertLabelToNumber(x))

        # Remove oldest state
        localStates.popleft()
        pred = stateless.predict([testSet[i][4:]])
        stateless_accuarcy = stateless.predict_proba([testSet[i][4:]])
        stateless_accuarcy = max(stateless_accuarcy[0])
        total_accuarcy.append(stateless_accuarcy)
        if stateless_accuarcy < THRESHOLD:
            pred = [max(set(localStates), key=localStates.count)]

        t2 = datetime.datetime.now()
        inferenceTime.append((t2 - t1).total_seconds())
        localStates.append(pred[0])
        predictedStates.append(pred[0])
        correctStates.append(testSet[i][3])

        currTime = int(testSet[i][1]) - startTime
        allData.append((pred[0], testSet[i][3], stateless_accuarcy, currTime))

    print(
        f"min {min(total_accuarcy)} averate {sum(total_accuarcy) / len(total_accuarcy)}"
    )
    accuracy = metrics.accuracy_score(correctStates, predictedStates)
    return predictedStates, correctStates, round(accuracy, 2), inferenceTime, allData


def plot_confusion_matrix(predictedStates, correctStates, title):
    matrix = confusion_matrix(
        y_true=correctStates, y_pred=predictedStates, labels=LABELS
    )
    matrix = matrix.astype("float") / matrix.sum(axis=1)[:, np.newaxis]
    plt.figure(figsize=(16, 7))
    sns.set(font_scale=1.4)
    map = sns.heatmap(
        matrix, annot=True, annot_kws={"size": 10}, cmap=plt.cm.Greens, linewidths=0.2
    )
    tick_marks = np.arange(len(LABELS)) + 0.5
    plt.xticks(tick_marks, LABELS, rotation=0)
    plt.yticks(tick_marks, LABELS, rotation=0)
    plt.xlabel("Predicted label")
    plt.ylabel("True label")
    plt.title(title)
    map.get_figure().savefig(
        FILE_PATH + "classification/" + title + ".png", bbox_inches="tight"
    )


def main(model, time, state):
    state = int(state)
    parse_configuration()

    metaOperatedTestSet, metaPacketTestSet = read_attributes()

    statelessP, statelessPF = parse_models(time, model)

    pred, correct, accuracy, inference, allData = test_model(
        state, statelessPF, metaOperatedTestSet
    )

    print("The accuracy is ", accuracy)

    # plot_confusion_matrix(pred, correct, f"Stateful packet {pcap} {accuracy}")
    plot_confusion_matrix(pred, correct, f"Stateful packet and flow  {accuracy}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("model")
    parser.add_argument("time")
    parser.add_argument("state")
    parser.add_argument("threshold")
    args = parser.parse_args()
    THRESHOLD = float(args.threshold)
    main(args.model, args.time, args.state)
