import socket
from argparse import ArgumentParser
import re
import sys

# Version: 0.1
# Copyright Cyber Blacksmith

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
            self.ScanAddress(target, port)
        else:
            print("Address error, terminating scan.")

    
    def IsTargetValid(self, item : str) -> bool:
        result = False
        pattern = ""
        match = re.search(pattern, item)
    
        result = match != None
        if match:
            print(f"Target: {item}")
        else:
            print(f"Unable to identify target: \'{item}\' based on supplied parameter. Please supply the target as the last parameter.")

        return result;

    def ScanAddress(self, address: str, port: str):

        portsToScan = self.PortTokenizer(port)
        
        socketMode = socket.SOCK_STREAM
        if(self.Arguments['mode'] == "UDP"):
            socketMode = socket.SOCK_DGRAM
        
        for aPort in portsToScan:
            with socket.socket(socket.AF_INET, socketMode) as targetSocket:
                try:
                        targetSocket.settimeout(self.defaultSocketTimeout)           
                        targetSocket.connect((address, aPort))
                        print(f"Port {aPort} is open.")
                except ConnectionAbortedError as e:
                    continue 
                except ConnectionRefusedError as e:
                    continue
                except ConnectionResetError as e:
                    continue
                except ConnectionError as e: 
                    continue
                except TimeoutError as e:
                    continue
                except Exception as e:
                    print(f"Unknown Error: {e}")
                finally:
                        targetSocket.close()

    def SetupArguments(self):
        self.Parser.add_argument('address', metavar='Address', type=str, help="The hostname or IP address of the target. Also supports subnet ranges using CIDR notation.")
        self.Parser.add_argument("-p","--port", dest="port", default="80", help="The Port(s) to scan. Can be comma delimited hyphenated.")
        self.Parser.add_argument("-m","--mode", dest="mode",choices=['TCP', 'UDP'], default="TCP", help="The protocol used during the scan (e.g. TCP, UDP.)")
        self.Parser.add_argument("-w","--wait", dest="timeout", default=50, type=int, help="The timeout in ms to wait for connections. Increase to slow scans.")
    def PortTokenizer(self, ports: str) -> [int]:
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

PyMap()