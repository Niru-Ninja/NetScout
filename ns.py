import socket
import threading
from ipaddress import ip_address

from os.path import exists
from json import dumps


def banner():
    print('\n\n')
    print('  ▄▄    ▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄   ▄▄ ▄▄▄▄▄▄▄ ')
    print(' █  █  █ █       █       █  █       █       █       █  █ █  █       █')
    print(' █   █▄█ █    ▄▄▄█▄     ▄█  █  ▄▄▄▄▄█       █   ▄   █  █ █  █▄     ▄█')
    print(' █       █   █▄▄▄  █   █    █ █▄▄▄▄▄█     ▄▄█  █ █  █  █▄█  █ █   █  ')
    print(' █  ▄    █    ▄▄▄█ █   █    █▄▄▄▄▄  █    █  █  █▄█  █       █ █   █  ')
    print(' █ █ █   █   █▄▄▄  █   █     ▄▄▄▄▄█ █    █▄▄█       █       █ █   █  ')
    print(' █▄█  █▄▄█▄▄▄▄▄▄▄█ █▄▄▄█    █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ █▄▄▄█  ')
    print('\n\n')


def printHelp(code):
    match code:
        case 0:
            print("\n")
            print("  help: Prints this.")
            print("  banner: Prints the banner.")
            print("\n  set: Changes an option before scanning:")
            print("       range: The range of IPs to scan. Use a middle dash (-) to indicate a range. Ex: 192.168.0.0-192.168.1.255")
            print("              You can express multiple ranges by separating them with spaces. Ex: 7.0.0.0-8.0.0.0 10.7.8.9-10.10.0.0")
            print("       ports: Ports to check if they are open on each ip.")
            print("       timeout: Time in seconds to give up the connection to a port.")
            print("       threads: Maximum number of threads to scan the ip range.")
            print("       file: File to save the results. Default is 'none' (Console output)")
            print("\n  show: Shows all the option values. IP range values could not show if the list is too long, use 'show range'.")
            print("       results: shows the previous scan results.")
            print("       range: shows the range of ip to be scanned.")
            print("\n  import: Imports an ip range from a file.")
            print("\n  scout: Starts the scan.")
            print("\n  exit: Closes the program.")
            print("\n")
        case 1:
            print("  ERROR: There is an invalid IP number.")
        case 2:
            print("  ERROR: There is a port number smaller than 0 or greater than 65535")
        case 3:
            print("  ERROR: maxip is not higher than minip")
        case 4:
            print("  ERROR: Missing arguments")
        case 5:
            print("  ERROR: Timeout must be a positive number")
        case 6:
            print("  ERROR: There is a port that is not a number")
        case 7:
            print("  ERROR: Number of threads should be >= 1")
        case 8:
            print("  ERROR: Too many arguments")
        case 9:
            print("  ERROR: File doesnt exists.")


def joinIPList(list):
    # Transforms a list of the style [127, 0, 0, 1] to "127.0.0.1"
    retMe = ""
    for i in list:
        retMe = retMe + str(i) + "."
    return retMe[:len(retMe)-1]


def validIP(IP):
    # Validates IPV4 IPs for user input.
    def isIPv4(s):
        try:
            return str(int(s)) == s and 0 <= int(s) <= 255
        except:
            return False
    if IP.count(".") == 3 and all(isIPv4(i) for i in IP.split(".")):
        return True
    return False


def validIPRange(range):
    #Validates an IPV4 range, for example: "15.0.0.0-15.255.255.255"
    ip_list = range.split("-")
    if len(ip_list) == 2:
        return validIP(ip_list[0]) and validIP(ip_list[1])
    else:
        return False


def validIPRangeList(rangeList):
    boolAcum = True
    for r in rangeList:
        boolAcum = boolAcum and validIPRange(r)
    return boolAcum


def validPortRange(portRange):
    # Validates all port numbers for user input.
    try:
        if all(0 <= int(i) <= 65535 for i in portRange):
            return True
        else:
            printHelp(2)
            return False
    except ValueError:
        printHelp(6)
        return False


def checkIP_and_Port(sock, IP, port, timeout):
    # Checks if a port is open on a given IP.
    sock.settimeout(timeout)
    result = sock.connect_ex((IP, port))
    if result == 0:
        return True
    else:
        return False


def ip_add1(minSplit, maxSplit):
    minSplit[3] = minSplit[3] + 1
    if minSplit[3] > 255:
        minSplit[3] = 0
        minSplit[2] = minSplit[2] + 1
        if minSplit[2] > 255:
            minSplit[2] = 0
            minSplit[1] = minSplit[1] + 1
            if minSplit[1] > 255:
                minSplit[1] = 0
                minSplit[0] = minSplit[0] + 1
                if minSplit[0] > maxSplit[0]:
                    return -1
    return minSplit


def ip_add(minSplit, numToAdd):
    # Adds a number to an ip list, for example:
    #[127, 0, 0, 1] + 300 = [127, 0, 1, 45]
    result = ip_address(joinIPList(minSplit)) + numToAdd
    result = result.exploded
    return list(map(lambda a: int(a), result.split(".")))


def ip_diff(maxip, minip):
    # Finds the difference between two ip lists, returns an int
    tr_maxip = ip_address(joinIPList(maxip))
    tr_minip = ip_address(joinIPList(minip))
    result = int(tr_maxip) - int(tr_minip) + 1
    return result


def thread_Check_IP_Range(minSplit, maxSplit, ports, timeout):
    global resultDict
    # Cycle to check all the IPs on a range:
    while(joinIPList(maxSplit) != joinIPList(minSplit)):
        # Start the socket to check the ports.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Check an individual IP:
            hasOpenPort = False
            portList = []
            for i in ports:
                if checkIP_and_Port(sock, joinIPList(minSplit), i, timeout):
                    hasOpenPort = True
                    portList.append(i)
            if hasOpenPort:
                resultDict[joinIPList(minSplit)] = portList
            # Move on to the next IP:
            minSplit = ip_add1(minSplit, maxSplit)
            if(minSplit == -1):
                break
            sock.close()
        except:
            print("Socket Failed")
            minSplit = ip_add1(minSplit, maxSplit)
            pass
    if joinIPList(maxSplit) == joinIPList(minSplit):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            hasOpenPort = False
            portList = []
            for i in ports:
                if checkIP_and_Port(sock, joinIPList(minSplit), i, timeout):
                    hasOpenPort = True
                    portList.append(i)
            if hasOpenPort:
                resultDict[joinIPList(minSplit)] = portList
            sock.close()
        except:
            print("Socket Failed")
            minSplit = ip_add1(minSplit, maxSplit)
            pass
    return


def start_scan(ipmin, ipmax, ports, timeout, maxThreadNum):
    # Convert the string ip values to a list of ints so we can add...
    minSplit = list(map(lambda a: int(a), ipmin.split(".")))
    maxSplit = list(map(lambda a: int(a), ipmax.split(".")))
    # Check if the maxip number is actually bigger than the minip.
    if isMaxIp(minSplit, maxSplit):
        # We have to calculate how many ips we need to scan:
        totalIPnum = ip_diff(maxSplit, minSplit)
        # Higher number of threads than ips to scan would be a waste...
        if maxThreadNum > totalIPnum: threadNum = totalIPnum
        else: threadNum = maxThreadNum
        # Inform the number of threads to be used and clear the dictionary for the next scan:
        if threadNum == 1: print("   Using " + str(threadNum) + " thread to scan "+ str(totalIPnum) + " IP...\n")
        else: print("   Using " + str(threadNum) + " threads to scan " + str(totalIPnum) + " IP...\n")
        # Now we calculate how many ips we give to each thread:
        ipsPerThread = (totalIPnum // threadNum) - 1
        ipsRemaining = totalIPnum % threadNum
        threadArr = []
        counter = 0
        # Setting up all the threads for scanning:
        if ipsPerThread == 0:
            while counter < totalIPnum:
                if(ipsRemaining > 0):
                    thread = threading.Thread(target=thread_Check_IP_Range, args=[
                        ip_add(minSplit, counter), 
                        ip_add(minSplit, counter+1),
                        ports, timeout])
                    ipsRemaining -= 1
                    counter += 2
                else:
                    thread = threading.Thread(target=thread_Check_IP_Range, args=[
                        ip_add(minSplit, counter), 
                        ip_add(minSplit, counter),
                        ports, timeout])
                    counter += 1
                thread.daemon = True
                threadArr.append(thread)
        else:
            while counter < totalIPnum:
                if(ipsRemaining > 0):
                    thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                        ip_add(minSplit, counter),
                                        ip_add(minSplit, counter+ipsPerThread+1),
                                        ports, timeout])
                    ipsRemaining -= 1
                    counter += ipsPerThread + 2
                else:
                    if counter + ipsPerThread + 1 > totalIPnum:
                        thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                            ip_add(minSplit, counter),
                                            maxSplit,
                                            ports, timeout])
                        thread.daemon = True
                        threadArr.append(thread)
                        break
                    else:
                        thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                            ip_add(minSplit, counter),
                                            ip_add(minSplit, counter+ipsPerThread),
                                            ports, timeout])
                        counter += ipsPerThread + 1
                thread.daemon = True
                threadArr.append(thread)
        # Running scan:
        for t in threadArr:
            t.start()
        for t in threadArr:
            t.join()
    else:
        printHelp(3)


def isMaxIp(minIP, maxIP):
    # Returns True if maxIP >= minIP
    return ip_address(joinIPList(maxIP)) >= ip_address(joinIPList(minIP))


def parse(com):
    # The structure of a command is: COMMAND PARAMETER1 PARAMETER2 [...] PARAMETER-N
	# The user can also use "" to simbolize that spaces are considered part of a parameter,
    # Like this: COMMAND PARAMETER1 "STRING WITH SPACES AS PARAMETER2" PARAMETER3 [...]
    com += " "
    acum = ""
    words = []

    onsameword = False
    for character in com:
        if character == '"' or character == "'": 
            onsameword = not onsameword
            continue
        if onsameword: acum += character
        elif character != " ": acum += character
        else:
            words.append(acum)
            acum = ""
    return words


banner()
line = input(" > ")
parsed = parse(line)
command = parsed[0]

ipRange = ["127.0.0.1-127.0.0.1"]
ports = [80, 443]
timeout = 1
maxThreadNum = 1
threadNum = 1
filepath = 'none'

# Create a Dictionary to save results and print only those that have open ports:
resultDict = {}

while command != "exit":
    if command == "banner":
        banner()
    elif command == "set":
        if parsed[1] == "range" or parsed[1] == "iprange" or parsed[1] == "ran" or parsed[1] == "rng":
            if validIPRangeList(parsed[2:]): 
                ipRange = parsed[2:]
            else:
                printHelp(1)
        elif parsed[1] == "timeout":
            try:
                if int(parsed[2]) > 0:
                    timeout = int(parsed[2])
                else:
                    printHelp(5)
            except IndexError:
                printHelp(4)
            except ValueError:
                printHelp(5)
        elif parsed[1] == "ports" or parsed[1] == "port":
            if(validPortRange(parsed[2:])):
                ports.clear()
                for i in parsed[2:]:
                    ports.append(int(i))
        elif parsed[1] == "threads" or parsed[1] == "thread":
            try:
                if(int(parsed[2]) >= 1):
                    maxThreadNum = int(parsed[2])
                else:
                    printHelp(7)
            except IndexError:
                printHelp(4)
        elif parsed[1] == 'file':
            if parsed[2].lower() != 'none':
                if exists(parsed[2]):
                    print("\n")
                    answer = input("  WARNING: " + parsed[2] + " already exists. Do you want to ovewrite it? y/n. ")
                    answer = answer.lower()
                    if answer == 'y' or answer == 'yes':
                        filepath = parsed[2]
                    print("\n")
                else:
                    filepath = parsed[2]
            else:
                filepath = 'none'

    elif command == "show":
        print("\n")
        if len(parsed)>1:
            if parsed[1] == "result" or parsed[1] == "results": 
                print(resultDict)
            elif parsed[1] == "range" or parsed[1] == "iprange" or parsed[1] == "ran" or parsed[1] == "rng":
                for r in ipRange: 
                    print(r)
        else:
            if len(ipRange) < 4:
                print("       Range:       ", ipRange)
            print("       Ports:       ", ports)
            print("       Timeout:     ", timeout)
            print("       Threads:     ", maxThreadNum)
            print("       File:        ", filepath)
        print("\n")
    elif command == "import":
        if len(parsed) == 2:
            if exists(parsed[1]):
                rangeFile = open(parsed[1], "r")
                rangeList = rangeFile.readlines()
                rangeFile.close()
                rangeList = [line.strip() for line in rangeList]
                if validIPRangeList(rangeList):
                    ipRange = rangeList
                else:
                    printHelp(1)
            else:
                printHelp(9)
        elif len(parsed)<2:
            printHelp(4)
        else:
            printHelp(8)
    elif command == "scout" or command == "scan" or command == "fire" or command == "run":
        resultDict.clear()
        for r in ipRange:
            currentRange = r.split("-")
            ipmin = currentRange[0]
            ipmax = currentRange[1]
            start_scan(ipmin, ipmax, ports, timeout, maxThreadNum)
        # Showing the results or writing them in a file:
        if filepath == 'none':
            if resultDict:
                print(resultDict)
                print("\n")
        else:
            if resultDict:
                print("  Found " + str(len(resultDict)) + " IPs with open ports.\n")
            outputFile = open(filepath, "w")
            outputFile.write(dumps(resultDict, indent=2))
            outputFile.close()
        if not resultDict:
            print("  No open ports found.\n")
    else:
        printHelp(0)

    line = input(" > ")
    parsed = parse(line)
    command = parsed[0]
