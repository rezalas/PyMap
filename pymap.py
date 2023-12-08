import socket
from argparse import ArgumentParser
import re
import sys


class PyMap:

    def __init__(self):
        #declare defaults
        self.defaultSocketTimeout = 2.0
        self.Parser = ArgumentParser(prog="PyMap",
            description="Scans a target IP or network to identify open ports. Parameters can be provided to modify the scanner profile.",
            epilog="Copyright Cyber Blacksmith")
        
        self.SetupArguments()
        self.Arguments = vars(self.Parser.parse_args())

        # Verify that at least one argument 
        if(len(self.Arguments['address']) == None):
            print("Invalid argument set provided, provide at least one target.")
        
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

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as targetSocket:
            for aPort in portsToScan:
                try:
                        targetSocket.settimeout(self.defaultSocketTimeout)           
                        targetSocket.connect((address, aPort))
                        response = targetSocket.recv(1024)
                        print(response)
                        print(f"Port {aPort} is open.")
                        targetSocket.close()
                except ConnectionAbortedError as e:
                    return 
                except ConnectionRefusedError as e:
                    print(f"connection refused: {aPort}")
                    return
                except ConnectionResetError as e:
                    return
                except ConnectionError as e: 
                    return
                except TimeoutError as e:
                    return
                except Exception as e:
                    print(f"Unknown Error: {e}")

    def SetupArguments(self):
        self.Parser.add_argument('address', metavar='Address', type=str, help="The hostname or IP address of the target. Also supports subnet ranges using CIDR notation.")
        self.Parser.add_argument("-p","--port", dest="port", default="80", help="The Port(s) to scan. Can be comma delimited hyphenated.")
        self.Parser.add_argument("-m","--mode", dest="mode", default="TCP", help="The protocol used during the scan (e.g. TCP, UDP.)")

    def PortTokenizer(self, ports: str) -> [int]:
        result = []
        if ports.count(',') > 0:
            tokens = ports.split(',')
            for token in tokens:
                result.extend(self.PortTokenizer(token))
        elif ports.count('-') > 0:
            tokens = ports.split('-')
            start = tokens[0]
            end = tokens[1]
            if(start == end):
                print("Error: Port ranges cannot contain the same number twice.")
            if(start >= end):
                print("Error: Port ranges must be formatted in order from least to greatest, e.g. 10-100.")
                exit(-1)
            result.extend(range(start, end))
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