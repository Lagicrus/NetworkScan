import ipaddress, subprocess, socket, sys, os, shlex, struct, getopt
from ctypes import windll, create_string_buffer

class all():
    def LANScan():
        global net_addr, all_hosts, started
        #Get the IP Net to scan
        net_addr = input("Enter a network address (ex.192.168.1.0): ")
        print("")
        net_addr = net_addr + "/24"
        try:
            # Create the network
            ip_net = ipaddress.ip_network(net_addr)
            # Get all hosts on that network
            all_hosts = list(ip_net.hosts())
            all.LANScan2()
        except KeyboardInterrupt:
           print("\nKeyboard Interrupt\n")
           started = True

    def LANScan2():
        global started, finished
        # Configure subprocess to hide the console window
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = subprocess.SW_HIDE
        # For each IP address in the subnet,
        iw = 0
        iq = 0
        for i in range(len(all_hosts)):
            output = subprocess.Popen(['ping', '-n', '1', '-w', '500', str(all_hosts[i])], stdout=subprocess.PIPE, startupinfo=info).communicate()[0]
            #If the host cannot be reached eg doesnt respond
            if "Destination host unreachable" in output.decode('utf-8'):
                iw += 1
            #If the host takes to long to respond
            elif "Request timed out" in output.decode('utf-8'):
                iq += 1
            else:
                try:
                    hostn = socket.gethostbyaddr(str(all_hosts[i]))[0]
                except socket.herror:
                    hostn = "N/A"
                print(str(all_hosts[i]), "is Online" , "        ", hostn)

        input("\nFinished Scanning")
        print("")
        finished = True
        started = False

    def ping():
        global output, started
        IP = input(formati.format("Enter IP: ")).lower()
        info = subprocess.STARTUPINFO()
        info.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        info.wShowWindow = subprocess.SW_HIDE
        #Snips of the front of the URL so that it can be pinged
        if "http://" in IP:
            IP = IP[7:]
        elif "https://" in IP:
            IP = IP[8:]
        output = subprocess.Popen(["ping","-n","1",str(IP)],stdout=subprocess.PIPE,startupinfo=info).communicate()[0]
        #If any errors occur with Ping then deal with it
        if "Ping request could not find host" in output.decode("utf-8"):
            print(formatt.format("\nPlease enter a valid IP address\n"))
            started = "TrueP"
        elif "Destination host unreachable" in output.decode('utf-8'):
            print("\nDestination host unreachable")
            print(formatt.format("%s is Offline"%(str(IP))),"\n")
        elif "Request timed out" in output.decode('utf-8'):
            print("\nRequest timed out")
            print(formatt.format("%s is Offline"%(str(IP))),"\n")
        elif "transmit failed" in output.decode("utf-8"):
            print("\nTransmit Failed")
            print(formatt.format("%s is Offline"%(str(IP))),"\n")
        elif "General failure" in output.decode("utf-8"):
            print("\nGeneral Failure")
            print(formatt.format("%s is Offline"%(str(IP))),"\n")
        else:
            all.reply()

    def reply():
        global started, finished
        #This is the stupid way in which it grabs the details to reply with later when it prints out the stats
        for line in output.decode("utf-8").splitlines():
            if "Approximate" in line:
                mini = line
            if "Minimum" in line:
                approy = line
            if "Reply from" in line:
                reply = line
            if "Sent" in line:
                packet = line
        timesrun = 0
        for wordsi in approy.split():
            timesrun += 1
            if timesrun == 9:
                averagems = wordsi
                break
        timesrun = 0
        for wordttl in reply.split():
            timesrun += 1
            if timesrun == 6:
                TTL = int(wordttl[4:])
        timesrun = 0
        for wordpackets in packet.split():
            timesrun += 1
            if timesrun == 4:
                packets = wordpackets[:1]
                packets = int(packets)
            if timesrun == 11:
                loss = wordpackets[1:]
                loss = loss[:1]
        print("")
        print(formatt.format("It took %s hops to get to its destination"%(64 - TTL)))
        #print(formatt.format("It went through %s routes and switches to get there"%(64 - TTL)))
        print(formatt.format("Average time to destination is %s"%(averagems)))
        print(formatt.format("Sent %s packets to get their with a %s%% loss"%(packets,loss)),"\n")
        finished = True
        started = False
    def port():
        #The popular ports that you might ping
        portlist = {1:"TCP",5:"RJE",7:"ECHO",18:"MSP",20:"FTP Data",21:"FTP Control",22:"SSH",23:"Telnet",25:"SMTP",45:"Internet Message Protocol",47:"NI FTP",53:"DNS",57:"MTP",66:"Oracle SQL*NET",80:"HTTP",89:"SU/MIT Telnet Gateway",92:"Network Printing Protocol",93:"Device Control Protocol",107:"Remote Telnet Service",109:"POP2",110:"POP3",115:"SFTP",117:"UUCP",118:"SQL",143:"IMAP",156:"SQL Service/Server",161:"SNMP",194:"IRC",197:"DLS",443:"HTTPS",546:"DHCP Client",547:"DHCP Server",8080:"HTTP Alt",8008:"HTTP Alt"}
        global IP, Port, started
        PortCheck = False
        #Grab the IP to port test
        IP = input(formati.format("Enter IP: ")).lower()
        while PortCheck != True:
            Port = input(formati.format("Enter Port: "))
            if Port.isnumeric() == True:
                Port = int(Port)
                PortCheck = True
            else:
                if Port == "A":
                    PortCheck = True
                else:
                    print("Please enter a number")
        TimeOut = 3
        socket.setdefaulttimeout(TimeOut)
        print("Starting Scan")
        print("")
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        #If the response is A then test ALL PORTS
        if Port == "A":
            for portA in range(1,65000):
                result = s.connect_ex((IP,portA))
                if portA in portlist:
                    if result == 0:
                        print("%s:%s is open (%s)"%(IP,portA,portlist[portA]))
                    else:
                        print("%s:%s is closed (%s)"%(IP,portA,portlist[portA]))
                else:
                    if result == 0:
                        print("%s:%s is open"%(IP,portA))
                    else:
                        print("%s:%s is closed"%(IP,portA))
        #If it knows what the port is
        elif Port in portlist:
            result = s.connect_ex((IP,Port))
            if result == 0:
                print("%s:%s is open (%s)"%(IP,Port,portlist[Port]))
            elif result == 10035:
                print("%s:%s is closed (%s)"%(IP,Port,portlist[Port]))
            else:
                print("%s:%s is closed (%s)"%(IP,Port,portlist[Port]))
        else:
            result = s.connect_ex((IP,Port))
            if result == 0:
                print("%s:%s is open"%(IP,Port))
            elif result == 10035:
                print("%s:%s is closed"%(IP,Port))
            else:
                print("%s:%s is closed"%(IP,Port))

def startup():
    global idlecheck, centre, formatt, formati
    #If it is running in console which is detected by the idlelib.run not being in the running modules
    if "idlelib.run" not in sys.modules:
        #figure out the width of the screen
        h = windll.kernel32.GetStdHandle(-12)
        csbi = create_string_buffer(22)
        resolution = windll.kernel32.GetConsoleScreenBufferInfo(h,csbi)
        (bufx,bufy,curx,cury,wattr,left,top,right,bottom,maxx,maxy) = struct.unpack("hhhhHhhhhhh",csbi.raw)
        sizex = right - left + 1
        sizey = bottom - top + 1
        idlecheck = True
        centre = int(sizex) #42 because 43 creates the minimum for 1 space
        formatt = "{:^%s}"%(centre-1)
        formati = "{:>%s}"%(int(centre/2))
    else:
        #else, default settings
        idlecheck = False
        formatt = "{:^70}"
        formati = "{:>45}"

def choice():
    global formati
    print("")
    choc = False
    while choc != True:
        #Gets the user to enter a option that they want to use
        cho = input(formati.format("P or L or K: ")).lower()
        if cho == "ping" or cho == "p":
            all.ping()
            choc = True
        elif cho == "lanscan" or cho == "l" or cho == "lan":
            all.LANScan()
            choc = True
        elif cho == "port" or cho == "k":
            all.port()
            choc = True
        else:
            print("Not a valid option\n")

def end():
    global finished
    if finished == True:
        finished = False

def argument(argv):
    #If it was run with arguments
    global IP
    global Port
    global all_hosts
    pk = 0
    try:
        opts, args = getopt.getopt(argv,"hp:k:l:",["ping=","knock=","lan="])
    except getopt.GetoptError:
        print("Example.py -p <IP/URL> -k <Port> -l <LAN eg 192.168.0.0>")
    for opt, arg in opts:
        #If they asked for help
        if opt in ("-h", "--help", "-?", "/?", "\?"):
            print("Example.py -p <IP/URL> -k <Port> -l <LAN eg 192.168.0.0>")
            sys.exit()
        #If they are using the lan scan setting
        elif opt in ("-l", "--lan"):
            try:
                net_addr = arg
                net_addr = net_addr + "/24"
                ip_net = ipaddress.ip_network(net_addr)
                all_hosts = list(ip_net.hosts())
                all.LANScan2()
            except:
                print("You did not enter a valid IP")
                print("")
                started = True
        #If they want to port test
        elif opt in ("-k", "--knock"):
            try:
                Port = int(arg)
            except:
                print("Please enter a valid number")
                break
        elif opt in ("-p", "--ping"):
            IP = arg
    for opt in opts:
        if "-p" in opt:
            pk += 1
        if "-k" in opt:
            pk += 1
    if pk == 1:
        ping2()
    elif pk == 2:
        port()

global finished
global started
finished = False
started = False

#If it detects you are running in terminal
if "idlelib.run" not in sys.modules:
        print("CONSOLE MODE")

#If it detets you are trying to run with arguments
if len(sys.argv) > 1:
    startup()
    argument(sys.argv[1:])
else:
    while True:
        startup()
        if finished == False and started == False:
            choice()
        elif finished == False and started == True:
            all.LANScan()
        elif finished == False and started == "TrueP":
            all.ping()
        else:
            choice()
        end()
