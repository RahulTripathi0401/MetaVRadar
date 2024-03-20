import csv
import argparse
import json


def parseConfig():
    global CONFIG
    with open("../config.json") as f:
        CONFIG = json.load(f)


def zeroPadding(byteSignatures):
    if len(byteSignatures) == 1:
        return [0, 0, 0]

    if len(byteSignatures) == 2:
        return [byteSignatures[0], 0, 0]
    if len(byteSignatures) == 3:
        return [byteSignatures[0], byteSignatures[1], 0]
    return byteSignatures


def getDomainName(DNSName, DefaultName="None"):
    if DNSName == "None":
        return DefaultName
    url = DNSName.split(".")
    k = len(url)
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


def getDomainPrefix(DNSName, IP="0.0.0.0"):
    name = DNSName.split(".")
    if not name[0]:
        return "None"
    return name[0]


def getDomainType(domainName):
    domainType = "None"
    primary = CONFIG["primaryDomains"]
    cloud = CONFIG["cloudDomains"]

    if "cdn" in domainName or domainName in cloud:
        domainType = "Cloud content"

    if domainName in primary:
        domainType = "Primary"

    if "." in domainName:
        domainType = "Time-critical activity"

    if domainType == "None":
        domainType = "Third-party service"

    return domainType


def main():
    parseConfig()
    filteredCount, consideredCount = 0, 0

    try:
        dataFile = open(f"../dataFormat/flow-Stats.csv", "r")
    except Exception as e:
        print(e)
        return

    with open(f"../dataFormat/TCPflowByteSignature.csv", "w") as file:
        csvWriter = csv.writer(file)
        csvReader = csv.reader(dataFile)
        header = [
            "StartTime",
            "EndTime",
            "DomainName",
            "DomainPrefix",
            "ServerPort",
            "1st",
            "2nd",
            "3rd",
            "Domain Type",
            "Duration",
        ]
        csvWriter.writerow(header)
        next(csvReader)
        for line in csvReader:
            domainName = line[1]
            byteSignatures = line[-1].split("|")
            byteSignatures = zeroPadding(byteSignatures)
            firstByte = int(byteSignatures[0])
            secondByte = int(byteSignatures[1])
            thirdByte = int(byteSignatures[2])
            dstPort = int(line[8])
            startTime = int(line[2])
            endTime = int(line[3])

            if int(firstByte) > 1000 or int(secondByte) > 300 or int(thirdByte) > 700:
                filteredCount += 1
                continue
            if int(firstByte) < 100 or int(secondByte) < 100 or int(thirdByte) < 100:
                filteredCount += 1
                continue

            consideredCount += 1
            outline = [
                startTime,
                endTime,
                getDomainName(domainName),
                getDomainPrefix(domainName),
                dstPort,
                firstByte,
                secondByte,
                thirdByte,
                getDomainType(domainName),
                endTime - startTime,
            ]
            csvWriter.writerow(outline)

        dataFile.close()
        print("filtered flow count: ", filteredCount)
        print("considered flow count: ", consideredCount)


if __name__ == "__main__":
    main()
