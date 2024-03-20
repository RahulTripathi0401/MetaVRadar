import json
import argparse
import csv
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn import preprocessing
from sklearn.metrics import confusion_matrix


def parse_configuration(pcap):
    with open("./config.json", "r") as f:
        config = json.load(f)
        global ABSOLOUTEPATH, FILE_PATH, INTERVALS, START_TIME, UDP_THRESHOLD, PRIMARY_DOMAIN, CLOUD_DOMAINS, PCAP, TIME_INTERVAL
        global LABELS, PATH
        try:
            PCAP = pcap
            TIME_INTERVAL = 10
            PATH = config["outputPath"]
            ABSOLOUTEPATH = config["outputPath"] + pcap + "/"
            FILE_PATH = config["outputPath"] + pcap + "/"
            UDP_THRESHOLD = int(config["udpThreshold"])
            PRIMARY_DOMAIN = config["primaryDomains"]
            CLOUD_DOMAINS = config["cloudDomains"]
            INTERVALS = config["Metaverses"][pcap]["intervals"]
            LABELS = [x for x in INTERVALS]
        except:
            print(f"{pcap} not defined in config file")


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
    metaOperated = parse_file(f"{FILE_PATH}MetaOperated-Attributes-{PCAP}.csv")
    metaPacket = parse_file(f"{FILE_PATH}MetaOperated-PacketAttributes-{PCAP}.csv")
    # with open(f"{FILE_PATH}AllAttributes-{PCAP}.csv") as csv_file:
    # with open(f"{FILE_PATH}Attributes-PacketAttributes-{PCAP}.csv") as csv_file:
    return metaOperated, metaPacket


def save_heatmap(data, depths, estimators, title):
    cmap = sns.cm.rocket_r
    fig = plt.figure(figsize=(16, 8))
    map = sns.heatmap(data, annot=True, linewidths=0.5, cmap=cmap, vmin=0, vmax=1)
    map.set_xticklabels(estimators)
    map.tick_params(axis="y", rotation=0)
    map.set_yticklabels(depths)
    plt.xlabel("Error Function", fontsize=10)
    plt.ylabel("Number of Hidden Nodes", fontsize=10)
    plt.title(title)
    print(f"saving {title}")
    map.get_figure().savefig(FILE_PATH + "classification/" + title, bbox_inches="tight")
    plt.clf()


def train(dataFrame, headers):
    X = dataFrame[headers]  # Features
    y = dataFrame["activity"]  # Labels
    ## Split dataset into training set and test set
    node_sizes = [5, 10, 20, 30, 50, 100, 200, 500]
    solvers = ["lbfgs", "sgd", "adam"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3
    )  # 70% training and 30% test
    data = []
    best_model = (0, 0)
    for node in node_sizes:
        solverData = []
        max_accuracy = 0
        for solver in solvers:
            clf = MLPClassifier(
                solver=solver, hidden_layer_sizes=(node,), random_state=1, max_iter=1000
            ).fit(X_train, y_train)
            ret = clf.score(X_test, y_test)
            y_pred = clf.predict(X_test)

            if ret > max_accuracy:
                best_model = (y_test, y_pred)
                max_accuracy = ret

            solverData.append(ret)
        data.append(solverData)

    save_heatmap(data, node_sizes, solvers, "Neural Network Hidden Layers vs Solvers")
    render_confusion_matrix(
        best_model[0], best_model[1], "Neural Network Confusion matrix"
    )


def render_confusion_matrix(y_test, y_pred, title):
    print(y_test)
    print(y_pred)
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


def main(pcap):
    parse_configuration(pcap)
    metaOperated, metaPacket = read_attributes()
    metaData, metaHeaders = format_data(metaOperated)
    train(metaData, metaHeaders)
    # metaData, metaHeaders = format_data(metaPacket)
    # train(metaData, metaHeaders)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap")
    args = parser.parse_args()
    main(args.pcap)
