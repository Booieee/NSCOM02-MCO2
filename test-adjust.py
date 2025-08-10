from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2

# Destination Unreachable error codes
error_msg = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
}

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
    hops = []  # Store hop results here

    for ttl in range(1, MAX_HOPS + 1):
        for tries in range(TRIES):
            destAddr = gethostbyname(hostname)
            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                packet = build_packet()
                send_time = time.time()
                mySocket.sendto(packet, (hostname, 0))

                ready = select.select([mySocket], [], [], TIMEOUT)

                if ready[0] == []:  # Timeout
                    if tries == TRIES - 1:  # Only add if last try failed
                        hops.append((ttl, "*", None))
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                recv_time = time.time()
                rtt_ms = round((recv_time - send_time) * 1000)

                icmpHeader = recvPacket[20:28]
                types, code, checksum_recv, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                if types == 0:  # Echo Reply (final destination)
                    hops.append((ttl, f"{addr[0]} (Echo Reply)", rtt_ms))
                    return hops
                elif types == 3:  # Destination Unreachable
                    reason = error_msg.get(code, f"Unknown code {code}")
                    hops.append((ttl, f"{addr[0]} (Destination Unreachable: {reason})", rtt_ms))
                    return hops
                elif types == 11:  # Time Exceeded
                    hops.append((ttl, f"{addr[0]} (Time Exceeded)", rtt_ms))
                else:
                    hops.append((ttl, f"{addr[0]} (Error: Type {types})", None))
                break

            except timeout:
                if tries == TRIES - 1:
                    hops.append((ttl, "*", None))
                continue

            finally:
                mySocket.close()

    return hops

if __name__ == "__main__":
    target = input("Enter target: ")
    results = get_route(target)

    print("\nTraceroute results:")
    print("{:<5} {:<50} {:<10}".format("TTL", "IP Address / Info", "RTT (ms)"))
    print("-" * 70)
    for ttl, ip, rtt in results:
        if ip == "*":
            print(f"{ttl:<5} {'*':<50} {'Timeout':<10}")
        else:
            print(f"{ttl:<5} {ip:<50} {rtt if rtt is not None else 'N/A':<10}")
