from socket import *
import os
import sys
import struct
import time
import select
from socket import error as socket_error
from socket import gaierror

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

def checksum(source_string):
    sum = 0
    max_count = (len(source_string) // 2) * 2
    count = 0
    while count < max_count:
        val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + val
        sum = sum & 0xffffffff
        count += 2
    if max_count < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum += (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    myID = os.getpid() & 0xFFFF
    seq = 1
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, myID, seq)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, myID, seq)
    packet = header + data
    return packet

def get_route(hostname):
    try:
        destAddr = gethostbyname(hostname)
    except gaierror:
        print(f"Could not resolve {hostname}")
        return

    print(f"Traceroute to {hostname} ({destAddr}), max hops={MAX_HOPS}")
    
    for ttl in range(1, MAX_HOPS + 1):
        for tries in range(TRIES):
            try:
                mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            except PermissionError:
                print("Permission denied: Please run as root/administrator")
                return
                
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            timeLeft = TIMEOUT

            try:
                d = build_packet()
                mySocket.sendto(d, (destAddr, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)

                if whatReady[0] == []:
                    print(f"{ttl}\t*\tRequest timed out.")
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect

                if timeLeft <= 0:
                    print(f"{ttl}\t*\tRequest timed out.")
                    continue

            except timeout:
                print(f"{ttl}\t*\tRequest timed out.")
                continue

            else:
                icmpHeader = recvPacket[20:28]
                types, code, checksum_recv, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                if types == 11:  # Time Exceeded
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(f"{ttl}\t{round((timeReceived - t)*1000)} ms\t{addr[0]}")

                elif types == 3:  # Destination Unreachable
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(f"{ttl}\t{round((timeReceived - t)*1000)} ms\t{addr[0]}")
                    return

                elif types == 0:  # Echo Reply
                    bytes_in_double = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes_in_double])[0]
                    print(f"{ttl}\t{round((timeReceived - timeSent)*1000)} ms\t{addr[0]}")
                    return

                else:
                    print(f"{ttl}\tError: ICMP type {types}")

                break

            finally:
                mySocket.close()

if __name__ == "__main__":
    targets = ["google.com", "dlsu.instructure.com", "dlsu.edu.ph"]
    for host in targets:
        get_route(host)
        print()  # Add blank line between traceroutes