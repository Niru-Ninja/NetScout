import socket
from unittest import result


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
            print("       minip: The minimum ip to start scanning.")
            print("       maxip: The maximum ip, las one to be scanned.")
            print("       ports: Ports to check if they are open on each ip.")
            print("\n  show: Shows the option values.")
            print("\n  scout: Starts the scan.")
            print("\n  exit: Closes the program.")
            print("\n")
        case 1:
            print("  ERROR: Invalid IP.")
        case 2:
            print("  ERROR: There is a port number smaller than 0 or greater than 65535")
        case 3:
            print("  ERROR: maxip is not higher than minip")
        case 4:
            print("  ERROR: Missing arguments")


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


def validPortRange(portRange):
    # Validates all port numbers for user input.
    return all(0 <= int(i) <= 65535 for i in portRange)


def checkIP_and_Port(sock, IP, port, timeout):
    # Checks if a port is open on a given IP.
    sock.settimeout(timeout)
    result = sock.connect_ex((IP, port))
    if result == 0:
        return True
    else:
        return False


def isMaxIp(minIP, maxIP):
    # Returns True if maxIP >= minIP
    for i in range(3):
        if maxIP[i] > minIP[i]:
            return True
        elif maxIP[i] < minIP[i]:
            return False
    return True


def parse(com):
    return com.split(" ")


banner()
line = input(" > ")
parsed = parse(line)
command = parsed[0]

ipmin = ipmax = '127.0.0.1'
ports = [80, 443]

while command != "exit":
    if command == "banner":
        banner()
    elif command == "set":
        if parsed[1] == "minip":
            try:
                if(validIP(parsed[2])):
                    ipmin = parsed[2]
                else:
                    printHelp(1)
            except IndexError:
                printHelp(4)
        elif parsed[1] == "maxip":
            try:
                if(validIP(parsed[2])):
                    ipmax = parsed[2]
                else:
                    printHelp(1)
            except IndexError:
                printHelp(4)
        elif parsed[1] == "ports" or parsed[1] == "port":
            if(validPortRange(parsed[2:])):
                ports.clear()
                for i in parsed[2:]:
                    ports.append(int(i))
            else:
                printHelp(2)
    elif command == "show":
        print("\n")
        print("       Minimum IP:  ", ipmin)
        print("       Maximum IP:  ", ipmax)
        print("       Ports:       ", ports)
        print("\n")
    elif command == "scout":
        # Convert the string ip values to a list of ints so we can add...
        minSplit = []
        maxSplit = []
        for i in ipmin.split("."):
            minSplit.append(int(i))
        for i in ipmax.split("."):
            maxSplit.append(int(i))
        # Check if the maxip number is actually bigger than the minip.
        if isMaxIp(minSplit, maxSplit):
            # Create a Dictionary to save results and print only those that have open ports:
            resultDict = {}
            hasOpenPort = False
            portList = []
            # Start the socket to check the ports.
            # Cycle to check all the IPs on a range:
            while(joinIPList(maxSplit) != joinIPList(minSplit)):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # Check an individual IP:
                hasOpenPort = False
                portList = []
                for i in ports:
                    if checkIP_and_Port(sock, joinIPList(minSplit), i, 2):
                        hasOpenPort = True
                        portList.append(i)
                if hasOpenPort:
                    resultDict[joinIPList(minSplit)] = portList
                # Move on to the next IP:
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
                                break
                sock.close()
            if joinIPList(maxSplit) == joinIPList(minSplit):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                hasOpenPort = False
                portList = []
                for i in ports:
                    if checkIP_and_Port(sock, joinIPList(minSplit), i, 2):
                        hasOpenPort = True
                        portList.append(i)
                if hasOpenPort:
                    resultDict[joinIPList(minSplit)] = portList
                sock.close()
            print(resultDict)
        else:
            printHelp(3)
    else:
        printHelp(0)

    line = input(" > ")
    parsed = parse(line)
    command = parsed[0]
