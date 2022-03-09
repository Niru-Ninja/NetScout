import socket
import threading


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
            print("       maxip: The maximum ip, last one to be scanned.")
            print("       ports: Ports to check if they are open on each ip.")
            print("       timeout: Time in seconds to give up the connection to a port.")
            print("       threads: Number of threads to scan an ip range.")
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
        case 5:
            print("  ERROR: Timeout must be a positive number")
        case 6:
            print("  ERROR: There is a port that is not a number")
        case 7:
            print("  ERROR: Number of threads should be >= 1")


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
timeout = 2
threadNum = 1

# Create a Dictionary to save results and print only those that have open ports:
resultDict = {}

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
            if(int(parsed[2]) >= 1):
                threadNum = int(parsed[2])
            else:
                printHelp(7)

    elif command == "show":
        print("\n")
        print("       Minimum IP:  ", ipmin)
        print("       Maximum IP:  ", ipmax)
        print("       Ports:       ", ports)
        print("       Timeout:     ", timeout)
        print("       Threads:     ", threadNum)
        print("\n")
    elif command == "scout" or command == "scan":
        # Convert the string ip values to a list of ints so we can add...
        minSplit = list(map(lambda a: int(a), ipmin.split(".")))
        maxSplit = list(map(lambda a: int(a), ipmax.split(".")))
        # Check if the maxip number is actually bigger than the minip.
        if isMaxIp(minSplit, maxSplit):
            print("\n")
            hasOpenPort = False
            portList = []
            # Array containing all the ips that the user wants to scan.
            iparr = []
            while(joinIPList(maxSplit) != joinIPList(minSplit)):
                iparr.append(joinIPList(minSplit))
                minSplit = ip_add1(minSplit, maxSplit)
                if(minSplit == -1):
                    break
            if(minSplit != -1):
                iparr.append(joinIPList(minSplit))
            ipsPerThread = len(iparr) // threadNum
            ipsRemaining = len(iparr) % threadNum
            threadArr = []
            counter = 0
            if ipsPerThread == 1:
                while counter < len(iparr):
                    if(ipsRemaining > 0):
                        thread = threading.Thread(target=thread_Check_IP_Range, args=[
                            list(map(lambda a: int(a), iparr[counter].split("."))), 
                            list(map(lambda a: int(a), iparr[counter+1].split("."))),
                            ports, timeout])
                        ipsRemaining -= 1
                        counter += 2
                    else:
                        thread = threading.Thread(target=thread_Check_IP_Range, args=[
                            list(map(lambda a: int(a), iparr[counter].split("."))), 
                            list(map(lambda a: int(a), iparr[counter].split("."))),
                            ports, timeout])
                        counter += 1
                thread.daemon = True
                threadArr.append(thread)
            else:
                while counter < len(iparr):
                    if(ipsRemaining > 0):
                        try:
                            thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                             list(map(lambda a: int(a), iparr[counter].split("."))),
                                             list(map(lambda a: int(a), iparr[counter + ipsPerThread+1].split("."))),
                                             ports, timeout])
                            ipsRemaining -= 1
                            counter += ipsPerThread + 1
                        except IndexError:
                            thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                             list(map(lambda a: int(a), iparr[counter].split("."))),
                                             list(map(lambda a: int(a), iparr[len(iparr)-1].split("."))),
                                             ports, timeout])
                            thread.daemon = True
                            threadArr.append(thread)
                            break
                    else:
                        try:
                            thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                             list(map(lambda a: int(a), iparr[counter].split("."))),
                                             list(map(lambda a: int(a), iparr[counter + ipsPerThread].split("."))),
                                             ports, timeout])
                            counter += ipsPerThread
                        except IndexError:
                            thread = threading.Thread(target=thread_Check_IP_Range, args=[
                                             list(map(lambda a: int(a), iparr[counter].split("."))),
                                             list(map(lambda a: int(a), iparr[len(iparr)-1].split("."))),
                                             ports, timeout])
                            thread.daemon = True
                            threadArr.append(thread)
                            break
                    thread.daemon = True
                    threadArr.append(thread)
            for t in threadArr:
                t.start()
            for t in threadArr:
                t.join()
            print(resultDict)
            print("\n")
        else:
            printHelp(3)
    else:
        printHelp(0)

    line = input(" > ")
    parsed = parse(line)
    command = parsed[0]
