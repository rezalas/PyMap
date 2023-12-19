import socket
from argparse import ArgumentParser
import re
from concurrent.futures import ThreadPoolExecutor


version = "0.1"
# Copyright (c) 2023 Paul McDowell

class PyMap:


    def __init__(self):
        #declare defaults
        self.Parser = ArgumentParser(prog="PyMap",
            description="Scans a target IP or network to identify open ports. Parameters can be provided to modify the scanner profile.",
            epilog="Copyright Cyber Blacksmith")
        
        self.SetupArguments()
        self.Arguments = vars(self.Parser.parse_args())

        # Verify that at least one argument 
        if(len(self.Arguments['address']) == None):
            print("Invalid argument set provided, provide at least one target.")
        
        self.defaultSocketTimeout = (float(self.Arguments['timeout']) / 1000)
        # Check if the final argument is the address or network range.
        target = self.Arguments['address']
        port = self.Arguments['port']
        
        if(self.IsTargetValid(target)):
            # Scan here
            self.ProcessScans(target, port)
        else:
            print("Address error, terminating scan.")

    
    def IsTargetValid(self, item : str) -> bool:
        result = False
        pattern = r"^(?:[0-1]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-1]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-1]?\d{1,2}|2[0-4]\d|25[0-5])\.(?:[0-1]?\d{1,2}|2[0-4]\d|25[0-5])(?:\/[0-2]?\d{1}|\/3[0-2]{1})?$"
        match = re.search(pattern, item)
    
        result = match != None
        if result:
            print(f"Target: {item}")
        else:
            print(f"Unable to identify target(s): \'{item}\' based on supplied address format. Please supply the target as the last parameter using standard notation.")

        return result;

    def ScanAddress(self, address: str, portsToScan: list[int], multiThreaded: bool = False):        
        socketMode = socket.SOCK_STREAM
        if(self.Arguments['mode'] == "UDP"):
            socketMode = socket.SOCK_DGRAM
        
        if(multiThreaded):
            with ThreadPoolExecutor(max_workers=self.Arguments['threads']) as executor:
                for aPort in portsToScan:
                    executor.submit(self.ScanPort, address, aPort, socketMode)
        else:
            for aPort in portsToScan:
                self.ScanPort(address, aPort, socketMode)
    
    def ScanPort(self, address: str, port: int, socketMode: int):
        with socket.socket(socket.AF_INET, socketMode) as targetSocket:
            try:
                    targetSocket.settimeout(self.defaultSocketTimeout)           
                    targetSocket.connect((address, port))
                    print(f"Port {port} is open.")
            except ConnectionAbortedError as e:
                pass 
            except ConnectionRefusedError as e:
                pass
            except ConnectionResetError as e:
                pass
            except ConnectionError as e: 
                pass
            except TimeoutError as e:
                pass
            except Exception as e:
                print(f"Unknown Error: {e}")
            finally:
                    targetSocket.close()
    
    #
    # Processes the addresses and ports to scan. If the address is a CIDR range, it will be converted to a list of addresses.
    # In the event that the address is a single address, it will be added to the list of addresses to scan, and use multi-threading
    # to scan the ports. Otherwise, it will scan each of the addresses in the list of addresses to scan using one thread per address 
    # based on the chosen number of threads.
    #
    def ProcessScans(self, address: str, port: str):
        addressesToProcess = []
        if '/' in address:
            addressesToProcess.extend(self.AddressesFromCIDR(address))
        else:
            addressesToProcess.append(address)

        portsToScan = self.PortTokenizer(port)

        if(len(addressesToProcess) == 1):
            self.ScanAddress(addressesToProcess[0], portsToScan, True)
        else:
            with ThreadPoolExecutor(max_workers=self.Arguments['threads']) as executor:
                for item in addressesToProcess:
                    executor.submit(self.ScanAddress, item, portsToScan)


    # 
    # Converts the network with CIDR notation to a list of addresses for
    # scanning. Skips over the network and broadcast address.
    #
    def AddressesFromCIDR(self, address: str) -> list[str]:
        resultSet = []
        try:
            addressTokens = address.split('/')
            CIDR = int(addressTokens[1])        
            addressSegments = addressTokens[0].split('.')
      
            addressBin = "".join(bin(int(octet) + 256 )[3:] for octet in addressSegments)
            CIDRBin = "".ljust(CIDR,"1") + "".rjust((32-CIDR),"0")

            networkBin = bin(int(addressBin,2) & int(CIDRBin,2))[2:].rjust(32,'0')
            #networkAddress = ".".join(map(str,[int(networkBin[0:8],2),int(networkBin[8:16],2), int(networkBin[16:24],2), int(networkBin[24:32],2)]))
            
            broadcastBin = "".join('1' if CIDRBin[i] == '0' else addressBin[i] for i in range(32))
            #broadcastAddress = ".".join(map(str, [int(broadcastBin[0:8],2),int(broadcastBin[8:16],2), int(broadcastBin[16:24],2),int(broadcastBin[24:32],2)]))

            startAddress = int(networkBin,2)
            endAddress = int(broadcastBin,2)
            
            while (startAddress != endAddress):
                if startAddress != int(networkBin,2):
                    binAddress = bin(int(startAddress))[2:].rjust(32,"0")
                    resultSet.append(".".join(map(str,[int(binAddress[0:8],2),int(binAddress[8:16],2),int(binAddress[16:24],2),int(binAddress[24:32],2)])))         
                startAddress += 1

        except ValueError as e:
            print("Invalid network or CIDR notation supplied for Address.")
            exit(-1)
        except Exception as e:
            print(f"Unexpected error processing CIDR: {e}")
            exit(-1)

        return resultSet       

    #
    # Converts the port string into a list of ports to scan.
    # Supports a mix of comma delimited and hyphenated ranges.
    #
    def PortTokenizer(self, ports: str) -> list[int]:
        result = []
        if ports.count(',') > 0:
            tokens = ports.split(',')
            for token in tokens:
                result.extend(self.PortTokenizer(token))
        elif ports.count('-') > 0:
            try:
                tokens = ports.split('-')
                start = int(tokens[0])
                end = int(tokens[1])
                if(start == end):
                    print("Error: Port ranges cannot contain the same number twice.")
                if(start >= end):
                    print("Error: Port ranges must be formatted in order from least to greatest, e.g. 10-100.")
                    exit(-1)
                if(end > 65535):
                    print(f"Invalid value supplied for one or more ports. Only ports from 1-65535 are allowed.")
                    exit(-1)
                result.extend(range(start, (end + 1)))
            except ValueError as e:
                print(f"Invalid value supplied as part of one or more ranges.")
        else:
            try:
                port = int(ports,10)
                if port > 65535 or port < 1:
                    raise ValueError(int)
                result.append(port)
            except ValueError as e:
                print(f"Invalid value supplied for one or more ports. Only ports from 1-65535 are allowed.")
                exit(-1)
        
        return result
    
    def SetupArguments(self):
        self.Parser.add_argument('address', metavar='Address', type=str, help="The hostname or IP address of the target. Also supports subnet ranges using CIDR notation.")
        self.Parser.add_argument("-p","--port", dest="port", default="80", help="The Port(s) to scan. Can be comma delimited hyphenated.")
        self.Parser.add_argument("-m","--mode", dest="mode",choices=['TCP', 'UDP'], default="TCP", help="The protocol used during the scan (e.g. TCP, UDP.)")
        self.Parser.add_argument("-w","--wait", dest="timeout", default=50, type=int, help="The timeout in ms to wait for connections. Increase to slow scans.")
        self.Parser.add_argument("-v","--version", dest="version", action="version", version=f'%(prog)s (version {version})', help="Displays the current version of PyMap.")
        self.Parser.add_argument("-t","--threads", dest="threads", default=8, type=int, help="The number of threads to use during the scan. Increase to speed up scans.")

PyMap()