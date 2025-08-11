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

def checksum(string):
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = string[count+1] * 256 + string[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + string[len(string) - 1]
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def build_packet():
    id = os.getpid() & 0xFFFF
    seq = 1
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, seq)
    data = struct.pack("d", time.time())
    myChecksum = checksum(header + data)

    if sys.platform == 'darwin':
        myChecksum = htons(myChecksum) & 0xffff
    else:
        myChecksum = htons(myChecksum)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, myChecksum, id, seq)

    packet = header + data
    return packet

def get_route(hostname):
    timeLeft = TIMEOUT
    destAddr = gethostbyname(hostname)
    
    print(f"Traceroute to {hostname} ({destAddr}), {MAX_HOPS} hops max:")
    print("{:<5} {:<50} {:<10}".format("TTL", "IP Address / Info", "RTT (ms)"))
    print("-" * 70)

    for ttl in range(1, MAX_HOPS):
        hop_found = False
        
        for tries in range(TRIES):
            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - t)

                if whatReady[0] == []: # Timeout
                    if tries == TRIES - 1:  # Only print if last try failed
                        print(f"{ttl:<5} {'*':<50} {'Timeout':<10}")
                        hop_found = True
                    continue

                recvPacket, addr = mySocket.recvfrom(1024)
                timeReceived = time.time()
                rtt_ping = round((timeReceived - t) * 1000)

                icmpHeader = recvPacket[20:28]
                types, code, checksum_recv, packetID, sequence = struct.unpack("bbHHh", icmpHeader)

                if types == 11:
                    print(f"{ttl:<5} {addr[0] + ' (Time Exceeded)':<50} {rtt_ping:<10}")
                    hop_found = True

                elif types == 3:
                    error_code = error_msg.get(code, f"Unknown code {code}")
                    print(f"{ttl:<5} {addr[0] + f' (Destination Unreachable: {error_code})':<50} {rtt_ping:<10}")
                    hop_found = True
                    return True  # Destination unreachable, stop traceroute
                    
                elif types == 0:
                    print(f"{ttl:<5} {addr[0] + ' (Echo Reply - Destination Reached)':<50} {rtt_ping:<10}")
                    hop_found = True
                    return True  # Reached destination, stop traceroute
                    
                else:
                    print(f"{ttl:<5} {addr[0] + f' (Error: Type {types})':<50} {'N/A':<10}")
                    hop_found = True
                break
            
            except timeout:
                if tries == TRIES - 1:
                    print(f"{ttl:<5} {'*':<50} {'Timeout':<10}")
                    hop_found = True
                continue

            finally:
                mySocket.close()
        
        if hop_found:
            time.sleep(0.1)
    
    return False 

if __name__ == "__main__":
    hostnames = ["google.com", "dlsu.instructure.com", "dlsu.edu.ph"]

    for i, target in enumerate(hostnames, 1):
        try:
            completed = get_route(target)
            if completed:
                print("Traceroute completed successfully!")
            else:
                print(f"Traceroute reached maximum hops ({MAX_HOPS}) without reaching destination.")
        except PermissionError:
            print(f"Permission denied: Administrator/root privileges required to create raw sockets.")
            break
        except Exception as e:
            print(f"Error during traceroute to {target}: {e}")
        
        if i < len(hostnames):
            print("\n" + "=" * 80)