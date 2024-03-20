from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn import metrics
from sklearn.metrics import confusion_matrix
import argparse
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import csv
import json
import sys
import os
import joblib
import shutil


def parse_configuration():
    with open("../config.json", "r") as f:
        config = json.load(f)
        global ABSOLOUTEPATH, FILE_PATH, INTERVALS, START_TIME, UDP_THRESHOLD, PRIMARY_DOMAIN, CLOUD_DOMAINS, PCAP, TIME_INTERVAL
        global LABELS
        try:
            TIME_INTERVAL = 10
            ABSOLOUTEPATH = config["outputPath"]
            FILE_PATH = "../dataFormat/"
            PRIMARY_DOMAIN = config["primaryDomains"]
            CLOUD_DOMAINS = config["cloudDomains"]
            INTERVALS = config["Metaverses"]["Multiverse2"]["intervals"]
            LABELS = [x for x in INTERVALS]
        except Exception as e:
            sys.exit(1)

    if not os.path.exists(FILE_PATH + "classification"):
        os.makedirs(FILE_PATH + "classification")

    for filename in os.listdir(FILE_PATH + "classification"):
        file_path = os.path.join(FILE_PATH + "classification", filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print("Failed to delete %s. Reason: %s" % (file_path, e))


def parse_file(file):
    print(file)
    contents = []
    with open(file) as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=",")
        for row in csv_reader:
            contents.append(row)
    return contents


def read_buff_attributes():
    metaOperated = parse_file(f"../dataFormat/Buffered-Packet-Flow.csv")
    metaPacket = parse_file(f"../dataFormat/Buffered-Packet.csv")
    return metaOperated, metaPacket


def read_attributes():
    metaOperated = parse_file(f"../dataFormat/MetaOperated-Attributes.csv")
    metaPacket = parse_file(f"../dataFormat/MetaOperated-PacketAttributes.csv")
    return metaOperated, metaPacket


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


def save_heatmap(data, depths, estimators, title, feature):
    cmap = sns.cm.rocket_r
    fig = plt.figure(figsize=(16, 8))
    map = sns.heatmap(data, annot=True, linewidths=0.5, cmap=cmap, vmin=0, vmax=1)
    map.set_xticklabels(depths)
    map.tick_params(axis="y", rotation=0)
    map.set_yticklabels(estimators)
    plt.xlabel("Tree Depth", fontsize=10)
    plt.ylabel("Number of Trees", fontsize=10)
    tempTitle = title + f" features {feature}"
    plt.title(tempTitle)
    print(f"saving {title}")
    map.get_figure().savefig(
        FILE_PATH + "classification/" + tempTitle, bbox_inches="tight"
    )
    plt.clf()


def render_confusion_matrix(y_test, y_pred, title):
    matrix = confusion_matrix(y_true=y_test, y_pred=y_pred, labels=LABELS)
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


def plot_most_accurate(most_accurate, title):
    for model in most_accurate:
        y_test, y_pred, estimator, depth, accuracy, clf = model
        tempTitle = (
            title
            + f"Model Number of Trees {estimator} Tree Depth {depth} Accuracy {round(accuracy, 2)}"
        )
        render_confusion_matrix(y_test, y_pred, tempTitle)
        dumpTitle = title.replace(" ", "_")
        joblib.dump(clf, f"{FILE_PATH}random_forrest_{dumpTitle}.joblib")
        return


def convertLabelToNumber(label):
    for x in range(len(LABELS)):
        if label == LABELS[x]:
            return x

    return -1


def train_data(dataFrame, headers, title):
    print(f"Processing data {title}")

    # Correlates to the number of trees
    estimators = [5, 10, 20, 40, 80, 120, 150, 200, 250, 300]
    # Depth of Tree
    depths = [1, 2, 4, 8, 16]
    # features
    features = [None]

    X = dataFrame[headers]  # Features
    y = dataFrame["activity"]  # Labels

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

    max_accuracy = 0
    most_accurate = []
    for feature in features:
        data = []
        for estimator in estimators:
            estimatorAccuracy = []
            for depth in depths:
                clf = RandomForestClassifier(
                    n_estimators=estimator, max_depth=depth, max_features=feature
                )
                clf.fit(X_train, y_train)
                y_pred = clf.predict(X_test)
                accuracy = metrics.accuracy_score(y_test, y_pred)

                if accuracy > max_accuracy:
                    max_accuracy = accuracy
                    most_accurate = [(y_test, y_pred, estimator, depth, accuracy, clf)]

                estimatorAccuracy.append(accuracy)
            data.append(estimatorAccuracy)
        save_heatmap(data, depths, estimators, title, feature)
        plot_most_accurate(most_accurate, title)


def calcuate_buffer(data, bufferlen):
    length = len(data)
    lengthAtttributes = len(data[0])
    dt = []
    for i in range(bufferlen + 1, length):
        cp = data[i].copy()
        for j in range(4, lengthAtttributes):
            val = 0
            for k in range(i - bufferlen, i):
                val += float(data[k][j])
            cp[j] = val / bufferlen
        dt.append(cp)

    return dt


def write_buffered_to_file(data, type):
    with open(f"../dataFormat/Buffered-{type}.csv", "w") as writer:
        print(f"Writing to file {type}")
        csv_writer = csv.writer(writer)
        csv_writer.writerows(data)


def createBuffer(buflen):
    metaPF, metaP = read_attributes()
    bufflen = int(buflen)
    data = calcuate_buffer(metaPF, bufflen)
    write_buffered_to_file(data, "Packet-Flow")
    data = calcuate_buffer(metaP, bufflen)
    write_buffered_to_file(data, "Packet")


def main(buflen):
    parse_configuration()
    createBuffer(buflen)
    metaOperated, metaPacket = read_attributes()
    metaData, metaHeaders = format_data(metaOperated)
    metaDataPacket, metaPacketHeaders = format_data(metaPacket)
    train_data(metaData, metaHeaders, "MetaOperated Attributes Packet and Flow ")
    train_data(metaDataPacket, metaPacketHeaders, "Meta Operated Packet Attributes ")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("buflen")
    args = parser.parse_args()
    main(args.buflen)
