import argparse
import csv
import json


def parseConfig():
    global CONFIG
    with open("../config.json") as f:
        CONFIG = json.load(f)


def zeroPadding(byteSignatures):
    if len(byteSignatures) <= 10:
        resultArray = []

        for i in range(0, len(byteSignatures) - 1):
            resultArray.append(byteSignatures[i])

        for i in range(len(byteSignatures) - 1, 10):
            resultArray.append(0)

        return resultArray

    return byteSignatures


def getDomainName(DNSName, DefaultName="None"):
    if DNSName == "None":
        return DefaultName
    url = DNSName.split(".")
    # to make sure we get domain suffix
    k = len(url)
    h = 0
    while (
        url[len(url) - k] == "com"
        or url[len(url) - k] == "gov"
        or url[len(url) - k] == "org"
        or url[len(url) - k] == "edu"
        or url[len(url) - k] == "net"
        or url[len(url) - k] == "co"
        or url[len(url) - k] == "mail"
    ):
        k = k + 1
    result_suffix = ""
    k = k - 1
    for h in range(k - 1, len(url) - 1):
        if h == k - 1:
            result_suffix = url[h]
        else:
            result_suffix = result_suffix + "." + url[h]
    return result_suffix


def getDomainPrefix(DNSName):
    name = DNSName.split(".")
    if name[0] == "":
        return "None"
    return name[0]


def main():
    parseConfig()
    filteredCount, consideredCount = 0, 0

    try:
        dataFile = open(f"../dataFormat/flow-Stats.csv", "r")
    except Exception as e:
        print("wrong name provided", e)
        return

    with open(f"../dataFormat/UDPflowByteSignature.csv", "w") as f:
        csvWriter = csv.writer(f)
        csvReader = csv.reader(dataFile)
        header = [
            "StartTime",
            "EndTime",
            "Duration",
            "ServerIP",
            "ServerPort",
            "1st",
            "2nd",
            "3rd",
            "4th",
            "5th",
            "6th",
            "7th",
            "8th",
            "9th",
            "10th",
            "detectedName",
        ]
        csvWriter.writerow(header)
        next(csvReader)

        for line in csvReader:
            domainName = line[1]
            proto = str(line[9])
            if domainName != "None" or proto != "2":
                continue

            byteSignatures = line[-1].split("|")
            byteSignatures = zeroPadding(byteSignatures)
            serverIP = line[6]
            dstPort = int(line[8])
            startTime = line[2]
            endTime = line[3]
            duration = line[4]

            if dstPort not in CONFIG["dstPorts"]:
                filteredCount += 1

            consideredCount += 1

            outline = [
                startTime,
                endTime,
                duration,
                serverIP,
                dstPort,
                byteSignatures[0],
                byteSignatures[1],
                byteSignatures[2],
                byteSignatures[3],
                byteSignatures[4],
                byteSignatures[5],
                byteSignatures[6],
                byteSignatures[7],
                byteSignatures[8],
                byteSignatures[9],
            ]
            csvWriter.writerow(outline)

        dataFile.close()
        print("filtered flow count: ", filteredCount)
        print("considered flow count: ", consideredCount)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    main()
