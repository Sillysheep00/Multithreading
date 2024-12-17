#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback
import threading
# NOTE: Do NOT import other libraries!

UDP_CODE = socket.IPPROTO_UDP
ICMP_ECHO_REQUEST = 8
MAX_DATA_RECV = 65535
MAX_TTL = 30

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.231.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=2, count=10)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=2, protocol='udp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_m = subparsers.add_parser('mtroute', aliases=['mt'],
                                         help='run traceroute')
        parser_m.set_defaults(timeout=2, protocol='udp')
        parser_m.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_m.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_m.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_m.set_defaults(func=MultiThreadedTraceRoute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        if len(sys.argv) < 2:
            parser.print_help()
            sys.exit(1)

        args = parser.parse_args()

        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: bytes) -> int: 
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer
    
    #Print Ping output
    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, seq: int, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationHostname, destinationAddress, seq, ttl, time))
        else:
            print("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms" % (packetLength, destinationAddress, seq, ttl, time))

    def printAdditionalDetails(self, host, numPacketsTransmitted, rtts):
        if len(rtts) > 0:
            print(f'--- {host} ping statistics ---')
            lossPercent = int((100.0 - 100.0*(len(rtts)/numPacketsTransmitted)))
            print(f'{numPacketsTransmitted} packets transmitted, {len(rtts)} received, {lossPercent}% packet loss')
            avgRTT = sum(rtts) / len(rtts)
            deviations = [abs(rtt - avgRTT) for rtt in rtts]
            mdev = sum(deviations) / len(deviations)
            minRTT = min(rtts)
            maxRTT = max(rtts)
            print("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms" % (1000*minRTT, 1000*avgRTT, 1000*maxRTT, 1000*mdev))

    #Print one line of traceroute output        
    def printMultipleResults(self, ttl: int, pkt_keys: list, hop_addrs: dict, rtts: dict, destinationHostname = ''):
        if pkt_keys is None:
            print(str(ttl) + '   * * *')
            return
        # Sort packet keys (sequence numbers or UDP ports)
        pkt_keys = sorted(pkt_keys)
        output = str(ttl) + '   '
        last_hop_addr = None
        last_hop_name = None

        for pkt_key in pkt_keys:
            # If packet key is missing in hop addresses, this means no response received: print '*'
            if pkt_key not in hop_addrs.keys():
                output += '* '
                continue
            hop_addr = hop_addrs[pkt_key]

            # Get the RTT for the probe
            rtt = rtts[pkt_key]
            if last_hop_addr is None or hop_addr != last_hop_addr:
                hostName = None
                try:
                    #Get the hostname for the hop
                    hostName = socket.gethostbyaddr(hop_addr)[0]
                    if last_hop_addr is None:
                        output += hostName + ' '
                    else: 
                        output += ' ' + hostName + ' '
                except socket.herror:
                    output += hop_addr + ' '
                last_hop_addr = hop_addr
                last_hop_name = hostName
                output += '(' + hop_addr + ') '

            output += str(round(1000*rtt, 3))
            output += ' ms  '      

        print(output)           
class ICMPPing(NetworkApplication):

    def __init__(self, args):
        host = None
        # 1. Look up hostname, resolving it to an IP address
        try:
            host = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return

        print('Ping to: %s (%s)...' % (args.hostname, host))

        # 1. Create an ICMP socket 
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)
        
        # 2. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 3. Send ping probes and collect responses 
        numPings = args.count
        seq_num = 0
        numPingsSent = numPings
        rtts = [] 
        while(numPings > 0):

            # 4. Do one ping approximately every second
            rtt, ttl, packetSize, seq = self.doOnePing(host, args.timeout, seq_num)

            # 5. Print out the RTT (and other relevant details) using the printOneResult method
            if rtt is not None:
                self.printOneResult(host, packetSize, rtt*1000, seq, ttl) 
                rtts.append(rtt)

            # 6. Sleep for a second     
            time.sleep(1) 

            # 7. Update sequence number and number of pings
            seq_num += 1
            numPings -= 1
        
        # 8. Print loss and RTT statistics (average, max, min, etc.)
        self.printAdditionalDetails(args.hostname, numPingsSent, rtts)

        # 9. Close ICMP socket
        self.icmpSocket.close()

    # Receive Echo ping reply
    def receiveOnePing(self, destinationAddress, packetID, sequenceNumSent, timeout):
        
        # 1. Wait for the socket to receive a reply
        echoReplyPacket = None
        isTimedout = False
        try:
            echoReplyPacket, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
        except socket.timeout as e:
            isTimedout = True
        
         # 2. Once received, record time of receipt, otherwise, handle a timeout
        timeRecvd = time.time()
        if isTimedout: # timeout
            return None, None, None, None
        
        # 3. Extract the IP header: 

        # The first 20 bytes is the IP header:  
        # (see: https://en.wikipedia.org/wiki/IPv4#/media/File:IPv4_Packet-en.svg):
        # 0          4             8          16          24           32 bits
        # |  Version | IP Hdr  Len |     TOS   |      Total Length     |
        # |         Identification             |Flag |  Fragment offset|
        # |        TTL             |  Protocol |     Header Checksum   |
        # |           Source IP  Address(32 bits, i.e., 4 bytes)       |
        # |           Destination IP Address (32 bits, i.e., 4 bytes)  |
        # |     Option (up to 40 bytes) this is an optional field      |

        ip_header = echoReplyPacket[:20]
        version_ihl, tos, total_length, identification, flags_offset, ttl, proto, checksum, src_ip, dest_ip = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        # Read the IP Header Length (using bit masking) 
        ip_header_len_field = (version_ihl & 0x0F)
        
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        payloadSize = total_length - ip_header_len
        
        # Now parse the ICMP header:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        #        <Optional timestamp (8 bytes) for     |
        #        a stateless ping>                     |        
        icmpHeader = echoReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, p_id, sequenceNumReceived = struct.unpack('!BBHHH', icmpHeader)
        
        # 5. Check that the ID and sequence numbers match between the request and reply
        if packetID != p_id or sequenceNumReceived != sequenceNumSent:
            return None, None, None, None
        
        # 6. Return the time of Receipt
        return timeRecvd, ttl, payloadSize, sequenceNumReceived
    
    # NOTE: This method can be re-used by ICMP traceroute
    # Send Echo Ping Request
    def sendOnePing(self, destinationAddress, packetID, sequenceNumber, ttl=None, dataLength=0):
        # 1. Build ICMP header
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        
        # 2. Checksum ICMP packet using given function
        # include some bytes 'AAA...' in the data (payload) of ping
        data = str.encode(dataLength * 'A')
        my_checksum = self.checksum(header+data)
        
        # 3. Insert checksum into packet
        # NOTE: it is optional to include an additional 8-byte timestamp (time when probe is sent)
        # in which case, a stateless ping can be implemented: the response will contain
        # the sending time so no need to keep that state, 
        # but we don't do that here (instead, we record sending time state in step 5)
        packet = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), packetID, sequenceNumber)
        
        if ttl is not None:
            self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        
        # 4. Send packet using socket
        self.icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending (state)
        timeSent = time.time()
        return timeSent
    
    def doOnePing(self, destinationAddress, timeout, seq_num):

        # 3. Call sendOnePing function
        packetID = random.randint(1, 65535)
        timeSent = self.sendOnePing(destinationAddress, packetID, seq_num, dataLength=48)

        # 4. Call receiveOnePing function
        timeReceipt, ttl, packetSize, seq = self.receiveOnePing(destinationAddress, packetID, seq_num, timeout)
        
        # 5. Compute RTT
        rtt = None
        if timeReceipt is None:
            print("Error receiveOnePing() has timed out")
        else:
            rtt = timeReceipt - timeSent

        # 6. Return total network delay, ttl, size and sequence number
        return rtt, ttl, packetSize, seq

class Traceroute(ICMPPing):

    def __init__(self, args):
        args.protocol = args.protocol.lower()
        
        # 1. Look up hostname, resolving it to an IP address
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
            #socket.getaddrinfo(args.hostname, None, socket.AF_INET6)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname) 
            return
        print('%s traceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))
        
        # 2. Initialise instance variables
        self.isDestinationReached = False
        
        # 3. Create a raw socket bound to ICMP protocol
        self.icmpSocket = None
        try:
            self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except socket.error as err:
            traceback.print_exception(err)
            exit(1)
        # 4. Set a timeout on the socket
        self.icmpSocket.settimeout(args.timeout)

        # 5. Run traceroute
        self.runTraceroute()

        # 6. Close ICMP socket
        self.icmpSocket.close()

    def runTraceroute(self):

        hopAddr = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        ttl = 1

        while(ttl <= MAX_TTL and self.isDestinationReached == False):
            if args.protocol == "icmp":
                self.sendIcmpProbesAndCollectResponses(ttl)
            
            elif args.protocol == "udp":
                self.sendUdpProbesAndCollectResponses(ttl)
            
            else:
                print(f"Error: invalid protocol {args.protocol}. Use udp or icmp")
                sys.exit(1)
            ttl += 1
    #send 3 ICMP traceroute probes per TTL and collect responses        
    def sendIcmpProbesAndCollectResponses(self, ttl):
        self.packetID = random.randint(35000, 65535)  # Unique packet identifier
        self.sequenceNumber = 0  # Initialize sequence number for probes
        
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()

        for _ in range(3):  # Send 3 probes per TTL
            timeSent = self.sendOneICMPProbe(self.dstAddress, ttl, self.sequenceNumber, self.packetID)
            pkt_keys.append(self.sequenceNumber)
            
            # Receive response
            packet, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if packet is None:
                continue
        
            _, icmpType = self.parseICMPTracerouteResponse(packet)
            
            # Check if destination reached
            if hopAddr == self.dstAddress and icmpType == 0:
                self.isDestinationReached = True
            
            if hopAddr is not None:
                rtts[self.sequenceNumber] = timeRecvd - timeSent
                hop_addrs[self.sequenceNumber] = hopAddr
            
            self.sequenceNumber += 1

        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, self.dstAddress)
                 
         
    def sendUdpProbesAndCollectResponses(self, ttl):
        
        hopAddr = None
        icmpType = None
        pkt_keys = []
        hop_addrs = dict()
        rtts = dict()
        
        numBytes = 52
        dstPort = 33439
        
        for _ in range(3): 
            # 1. Send one UDP traceroute probe
            dstPort += 1
            timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort , ttl, numBytes)
            
            # 2. Record a unique key (UDP destination port) associated with the probe
            pkt_keys.append(dstPort)
            
            # 3. Receive the response (if one arrives within the timeout)
            trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
            if trReplyPacket is None:
                # Nothing is received within the timeout period
                continue
            
            # 4. Extract destination port from the reply
            dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)   
            
            # 5. Check if we reached the destination
            if self.dstAddress == hopAddr and icmpType == 3:
                self.isDestinationReached = True

            # 6. If the response matches the request, record the rtt and the hop address 
            if dstPort == dstPortReceived:
                rtts[dstPort] = timeRecvd - timeSent
                hop_addrs[dstPort] = hopAddr
        # 7. Print one line of the results for the 3 probes        
        self.printMultipleResults(ttl, pkt_keys, hop_addrs, rtts, args.hostname)
    
    # Parse the response to UDP probe 
    def parseUDPTracerouteResponse(self, trReplyPacket):

        # 1. Parse the IP header
        dst_port = None
        # Extract the first 20 bytes 
        ip_header = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[:20])
        
        # 2. Read the IP Header Length (using bit masking) 
        ip_header_len_field = (ip_header[0] & 0x0F)
        
        # 3. Compute the IP header length
        # This field contains the length of the IP header in terms of 
        # the number of 4-byte words. So value 5 indicates 5*4 = 20 bytes. 
        ip_header_len = ip_header_len_field * 4
        
        # 4. Parse the outermost ICMP header which is 8 bytes long:
        # 0         8           16         24          32 bits
        #     Type  |    Code   |       Checksum       |
        #     Packet Identifier |       Sequence num   |
        # This header contains type, Code and Checksum + 4 bytes of padding (0's)
        # We only care about type field
        icmpType, _, _, _, _  = struct.unpack("!BBHHH", trReplyPacket[ip_header_len:ip_header_len + 8])
        
        # 5. Parse the ICMP message if it has the expected type
        if icmpType == 3 or icmpType == 11:
            ip_header_inner = struct.unpack("!BBHHHBBH4s4s", trReplyPacket[ip_header_len + 8:ip_header_len+28])
            
            # This is the original IP header sent in the probe packet
            # It should be 20 bytes, but let's not assume anything and extract the length
            # of the header
            ip_header_len_field = (ip_header_inner[0] & 0x0F)
            ip_header_inner_len = ip_header_len_field * 4
            
            # Extract the destination port and match using source port (UDP)
            _, dst_port, _, _ = struct.unpack('!HHHH', trReplyPacket[ip_header_len + 8 + ip_header_inner_len : ip_header_len + 8 + ip_header_inner_len + 8])
        
        return dst_port, icmpType
    
    # Parse the response to the ICMP probe
    def parseICMPTracerouteResponse(self, trReplyPacket):
        # Extract the first 20 bytes (IP header)
        ip_header = trReplyPacket[:20]
        
        # Unpack the IP header (first 20 bytes)
        ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
        
        # IP header length calculation
        ip_header_len = (ip_header_unpacked[0] & 0x0F) * 4  # Length of the IP header
        
        # Unpack the ICMP header from the packet (next 8 bytes after the IP header)
        icmp_header = trReplyPacket[ip_header_len:ip_header_len + 8]
        icmpType, code, checksum, recv_packetID, recv_seqNumber = struct.unpack('!BBHHH', icmp_header)
        
        # Check for ICMP types indicating the probe response
        if icmpType == 3 or icmpType == 11:
            # Unpack the inner IP header (embedded in ICMP message)
            inner_ip_header = trReplyPacket[ip_header_len + 8:ip_header_len + 28]
            inner_ip_header_len = (inner_ip_header[0] & 0x0F) * 4
            
            # Unpack inner ICMP header to retrieve the packet ID and sequence number
            inner_icmp_header = trReplyPacket[ip_header_len + 8 + inner_ip_header_len : ip_header_len + 8 + inner_ip_header_len + 8]
            _, _, _, inner_packetID, inner_seqNumber = struct.unpack('!BBHHH', inner_icmp_header)
            
            # Verify that this packet matches the expected packetID and sequenceNumber
            if inner_packetID == self.packetID and inner_seqNumber == self.sequenceNumber:
                return inner_seqNumber, icmpType
        
        elif icmpType == 0:
            self.isDestinationReached = True
            return self.sequenceNumber, icmpType

        return None, None

    def receiveOneTraceRouteResponse(self):

        timeReceipt = None
        hopAddr = None
        pkt = None

        # 1. Receive one packet or timeout
        try:
            pkt, addr = self.icmpSocket.recvfrom(MAX_DATA_RECV)
            timeReceipt = time.time()
            hopAddr = addr[0]
        
        # 2. Handler for timeout on receive
        except socket.timeout as e:
            timeReceipt = None
        
        # 3. Return the packet, hop address and the time of receipt
        return pkt, hopAddr, timeReceipt
    
    def sendOneICMPProbe(self, destinationAddress, ttl, sequenceNumber, packetID):
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, packetID, sequenceNumber)
        data = str.encode('A' * 48)  # 48 bytes of data to match the  other probes
        checksum = self.checksum(header + data)
        checksum = socket.htons(checksum)
        # Re-pack the header with the calculated checksum
        header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, packetID, sequenceNumber)
        packet = header + data
        
        self.icmpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        timeSent = time.time()
        self.icmpSocket.sendto(packet, (destinationAddress, 0))
       
        return timeSent

    def sendOneUdpProbe(self, destAddress, port, ttl, dataLength):

        # 1. Create a UDP socket
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, UDP_CODE)
        
        # 2. Use a socket option to set the TTL in the IP header
        udpSocket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        
        # 3. Send the UDP traceroute probe
        udpSocket.sendto(str.encode(dataLength * '0'), (destAddress, port))
        
        # 4. Record the time of sending
        timeSent = time.time()
        
        # 5. Close the UDP socket
        udpSocket.close()

        return timeSent
    
# A multi-threaded traceroute implementation
class MultiThreadedTraceRoute(Traceroute):
  
    def __init__(self, args):
        # 1. Initialise instance variables (add others if needed)
        self.dstAddress = None
        try:
            self.dstAddress = socket.gethostbyname(args.hostname)
        except socket.gaierror:
            print('Invalid hostname: ', args.hostname)
            return
        print('%s multitraceroute to: %s (%s) ...' % (args.protocol, args.hostname, self.dstAddress))
        self.ttl_results = {}  # Dictionary to store results for each TTL
        self.processed_hops = set() # Empty sets to track the hops that have already been processed
        args.protocol = args.protocol.lower()
        self.timeout = args.timeout
        self.send_complete = threading.Event()
         # NOTE you must use a lock when accessing data shared between the two threads  
        self.lock = threading.Lock()
        self.current_ttl = 1
        self.isDestinationReached = False
        
        self.icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.icmpSocket.settimeout(args.timeout)

        # 2. Create a thread to send probes
        self.send_thread = threading.Thread(target=self.send_probes)
        
        # 3. Create a thread to receive responses 
        self.recv_thread = threading.Thread(target=self.receive_responses)
        
        # 4. Start the threads
        self.send_thread.start()
        self.recv_thread.start()

        # 5. Wait until both threads are finished executing
        self.send_thread.join()
        self.recv_thread.join()
       
        # Print final results after all threads have finished
        self.print_final_results()
       
    # Thread to send probes
    def send_probes(self):
         
        while self.current_ttl <= MAX_TTL and not self.isDestinationReached:
            try:
            # Send three probes per TTL
                for i in range(3):  
                    if args.protocol == "icmp":
                        self.packetID = random.randint(35000, 65535)
                        self.sequenceNumber = i
                        timeSent = self.sendOneICMPProbe(self.dstAddress, self.current_ttl, self.sequenceNumber, self.packetID)  # Send ICMP probe
                        
                        # Receive response
                        trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
                        if trReplyPacket is None:
                            continue
                        
                        # Parse the ICMP response
                        recv_seqNumber, icmpType = self.parseICMPTracerouteResponse(trReplyPacket)
                        if hopAddr == self.dstAddress and icmpType == 0:  # ICMP Type 0 indicates destination reached
                            self.isDestinationReached = True
                        
                        # Calculate RTT and store in results
                        if hopAddr is not None:
                            rtt = timeRecvd - timeSent
                            
                            with self.lock: #Prevent race condition
                                if self.current_ttl not in self.ttl_results:
                                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}
                                #Update ttl_results
                                self.ttl_results[self.current_ttl]["pkt_keys"].append(self.sequenceNumber)
                                self.ttl_results[self.current_ttl]["hop_addrs"][self.sequenceNumber] = hopAddr
                                if self.sequenceNumber not in self.ttl_results[self.current_ttl]["rtts"]:
                                    self.ttl_results[self.current_ttl]["rtts"][self.sequenceNumber] = rtt
                        
                    elif args.protocol == "udp":        
                        dstPort = 33439 + i
                        numBytes = 52
                        timeSent = self.sendOneUdpProbe(self.dstAddress, dstPort, self.current_ttl, numBytes)

                        # Default values for no response case
                        hopAddr = None
                        timeRecvd = None
                        trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
                        if trReplyPacket is None:
                            with self.lock:  # Prevent race conditions
                                if self.current_ttl not in self.ttl_results:
                                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}
                                # Record the packet key with no associated address or RTT
                                if dstPort not in self.ttl_results[self.current_ttl]["pkt_keys"]:
                                    self.ttl_results[self.current_ttl]["pkt_keys"].append('*')     
                            continue
                        
                        dstPortReceived, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)
                        if self.dstAddress == hopAddr and icmpType == 3:
                            self.isDestinationReached = True

                        
                        if dstPort == dstPortReceived:
                            rtt = timeRecvd - timeSent
                            with self.lock:#Prevent Race Condition
                                if self.current_ttl not in self.ttl_results:
                                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}
                                #Update ttl result
                                self.ttl_results[self.current_ttl]["pkt_keys"].append(dstPort)
                                self.ttl_results[self.current_ttl]["hop_addrs"][dstPort] = hopAddr
                                if dstPort not in self.ttl_results[self.current_ttl]["rtts"]:
                                    self.ttl_results[self.current_ttl]["rtts"][dstPort] = rtt
                    # Sleep for a short period between sending probes
                    time.sleep(0.05)  # Small delay between probes
            except Exception as e:
                print(f" Error during TTL {self.current_ttl}, probe{i}:{e}")
            except TypeError as e:
                print(f"Type error in TTL {self.current_ttl}")


            # A final sleep before notifying the receive thread to exit
            time.sleep(args.timeout) 
            with self.lock:
                if self.current_ttl not in self.ttl_results:
                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}
                self.current_ttl += 1
        # Notify the other thread that sending is complete   
        self.send_complete.set()

    # Thread to receive response
    def receive_responses(self): 
        while True:
            try:
                if self.send_complete.is_set() and self.isDestinationReached:
                    break  # Exit if sending is complete and all TTLs have been processed
                
                trReplyPacket, hopAddr, timeRecvd = self.receiveOneTraceRouteResponse()
                if trReplyPacket:
                    if args.protocol == "icmp":
                        recv_seqNumber, icmpType = self.parseICMPTracerouteResponse(trReplyPacket)
                        if icmpType == 0:  # Destination reached for ICMP
                            self.isDestinationReached = True
                        rtt = time.time() -timeRecvd
                        with self.lock:
                            hop_key = (hopAddr,self.current_ttl,recv_seqNumber)
                            if hop_key not in self.processed_hops:
                                self.processed_hops.add(hop_key)
                                if self.current_ttl not in self.ttl_results:
                                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}

                                self.ttl_results[self.current_ttl]["pkt_keys"].append(recv_seqNumber)
                                self.ttl_results[self.current_ttl]["hop_addrs"][recv_seqNumber] = hopAddr
                                
                                if recv_seqNumber not in self.ttl_results[self.current_ttl]["rtts"]:
                                    
                                    self.ttl_results[self.current_ttl]["rtts"][recv_seqNumber] = rtt

                    elif args.protocol == "udp":
                        dst_port, icmpType = self.parseUDPTracerouteResponse(trReplyPacket)

                        if self.dstAddress == hopAddr and icmpType == 3:
                            self.isDestinationReached = True
                        
                        rtt = time.time() - timeRecvd
                       
                        with self.lock:
                            hop_key = (hopAddr, self.current_ttl, dst_port)
                            #To ensure hop address is already processed and is unique within ttl_results
                            if hop_key not in self.processed_hops:
                                self.processed_hops.add(hop_key)

                                if self.current_ttl not in self.ttl_results:
                                    self.ttl_results[self.current_ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}

                                self.ttl_results[self.current_ttl]["pkt_keys"].append(dst_port)
                                self.ttl_results[self.current_ttl]["hop_addrs"][dst_port] = hopAddr

                                if dst_port not in self.ttl_results[self.current_ttl]["rtts"]:
                                    self.ttl_results[self.current_ttl]["rtts"][dst_port] = rtt
            except TypeError as e:
                print("Type error occured")               
            except socket.timeout: 
                print("Socket timeout occurred, exiting receive loop.") 
                break
            except OSError as e:
                if e.errno == 9:  # Bad file descriptor
                    print("Socket closed, stopping receiving responses.")
                    break
                else:
                    print(f"Socket error: {e}")
    def print_final_results(self): 
        for ttl, results in self.ttl_results.items():
            if ttl not in self.ttl_results:
                self.ttl_results[ttl] = {"pkt_keys": [], "hop_addrs": {}, "rtts": {}}
           
            self.printMultipleResults(ttl, results["pkt_keys"], results["hop_addrs"], results["rtts"], self.dstAddress)
# You can test the web server as follows: 
# First, run the server in the terminal: python3 NetworkApplications.py web 
# Then, copy the following and paste to a browser's address bar: 127.0.0.1:8080/index.html
# NOTE: the index.html file needs to be downloaded from the Moodle (Dummy HTML file)
# and copied to the folder where you run this code
class WebServer(NetworkApplication):

    def __init__(self, args):
        print('Web Server starting on port: %i...' % args.port)
        
        # 1. Create a TCP socket 
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Bind the TCP socket to server address and server port
        serverSocket.bind(("", args.port))
        
        # 3. Continuously listen for connections to server socket
        serverSocket.listen(100)
        print("Server listening on port", args.port)
        
        while True:
            # 4. Accept incoming connections
            connectionSocket, addr = serverSocket.accept()
            print(f"Connection established with {addr}")
            
            # 5. Create a new thread to handle each client request
            threading.Thread(target=self.handleRequest, args=(connectionSocket,)).start()

        # Close server socket (this would only happen if the loop was broken, which it isn't in this example)
        serverSocket.close()

    def handleRequest(self, connectionSocket):
        try:
            # 1. Receive request message from the client
            message = connectionSocket.recv(MAX_DATA_RECV).decode()

            # 2. Extract the path of the requested object from the message (second part of the HTTP header)
            filename = message.split()[1]

            # 3. Read the corresponding file from disk
            with open(filename[1:], 'r') as f:  # Skip the leading '/'
                content = f.read()

            # 4. Create the HTTP response
            response = 'HTTP/1.1 200 OK\r\n\r\n'
            response += content

            # 5. Send the content of the file to the socket
            connectionSocket.send(response.encode())

        except IOError:
            # Handle file not found error
            error_response = "HTTP/1.1 404 Not Found\r\n\r\n"
            error_response += "<html><head></head><body><h1>404 Not Found</h1></body></html>\r\n"
            connectionSocket.send(error_response.encode())

        except Exception as e:
            print(f"Error handling request: {e}")

        finally:
            # Close the connection socket
            connectionSocket.close()

# TODO: A proxy implementation 
class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.bind(('127.0.0.1', args.port))
        self.serverSocket.listen(10)
        print("Proxy listening on port", args.port)
        
        # Initialize cache directory and dictionary to track cache
        self.cache_dir = './cache'
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
        self.cache = {}

        # Accept client requests
        while True:
            client_socket, addr = self.serverSocket.accept()

            # Create a thread to handle client request
            client_handler = threading.Thread(target=self.handle_client_request, args=(client_socket,))
            client_handler.start()

    def handle_client_request(self, client_socket):
        print("Received request:")

        # Read data sent by the client in the request
        request = b""
        client_socket.setblocking(False)
        while True:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                request += data
            except:
                break

        # Extract host and port from request
        host, port = self.extract_host_port_from_request(request)

        # Generate a unique cache filename based on URL
        cache_key = self.generate_cache_filename(request)

        # Check if the object is in the cache
        if cache_key in self.cache:
            print("Cache hit. Returning cached response.")
            self.send_cached_response(client_socket, cache_key)
        else:
            # No cache entry, fetch from server and cache the response
            self.fetch_and_cache_response(client_socket, host, port, request, cache_key)

        client_socket.close()

    def extract_host_port_from_request(self, request):
        # Get the value after the "Host:" string
        host_start = request.find(b'Host:') + len(b'Host:')
        host_end = request.find(b'\r\n', host_start)
        host_string = request[host_start:host_end].strip().decode('utf-8')
        if ':' in host_string:
            host, port_str = host_string.split(':', 1)
            port = int(port_str)
        else:
            host = host_string
            port = 80  # Default port for HTTP
        return host, port

    def generate_cache_filename(self, request):
        # Extract host and path from the request line to create a filename
        request_line_end = request.find(b'\r\n')
        request_line = request[:request_line_end].decode('utf-8')
        # Format: METHOD /path HTTP/version
        parts = request_line.split(' ')
        if len(parts) > 1:
            path = parts[1]
        else:
            path = '/'
        host, _ = self.extract_host_port_from_request(request)
        # Use host + path as the cache key and replace special chars
        cache_filename = f"{host}_{path}".replace('/', '_').replace(':', '_')
        return cache_filename

    def send_cached_response(self, client_socket, cache_key):
        # Send cached data to the client
        with open(os.path.join(self.cache_dir, self.cache[cache_key]), 'rb') as cache_file:
            client_socket.sendfile(cache_file)

    def fetch_and_cache_response(self, client_socket, host, port, request, cache_key):
        # Connect to the destination server
        destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        destination_socket.connect((host, port))
        destination_socket.sendall(request)

        # Create a cache file for the response
        cache_filename = f"{cache_key}.cache"
        cache_filepath = os.path.join(self.cache_dir, cache_filename)
        
        # Store cache file path in memory for quick access
        self.cache[cache_key] = cache_filename

        # Receive response from server, send to client, and save to cache
        with open(cache_filepath, 'wb') as cache_file:
            while True:
                data = destination_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)  # Send to client
                cache_file.write(data)  # Write to cache file

        destination_socket.close()
            

# NOTE: Do NOT delete the code below
if __name__ == "__main__":
        
    args = setupArgumentParser()
    args.func(args)
