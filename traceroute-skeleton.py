from socket import *
import os
import sys
import struct
import time
import select

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 3  # Windows tracert uses 3 pings per hop


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


def build_packet(seq):
    myID = os.getpid() & 0xFFFF
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
    print(f"Tracing route to {hostname} [{gethostbyname(hostname)}]")
    print(f"over a maximum of {MAX_HOPS} hops:\n")

    for ttl in range(1, MAX_HOPS + 1):
        times = []
        addr = None

        for seq in range(TRIES):
            mySocket = socket(AF_INET, SOCK_RAW, getprotobyname("icmp"))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)

            try:
                packet = build_packet(seq)
                mySocket.sendto(packet, (hostname, 0))
                t_start = time.time()
                ready = select.select([mySocket], [], [], TIMEOUT)

                if ready[0] == []:  # Timeout
                    times.append("*")
                    continue

                recvPacket, addr_info = mySocket.recvfrom(1024)
                addr = addr_info[0]
                time_received = time.time()
                icmp_header = recvPacket[20:28]
                types, code, checksum_recv, packetID, sequence = struct.unpack("bbHHh", icmp_header)

                rtt = round((time_received - t_start) * 1000)
                times.append(f"{rtt} ms")

                if types == 0:  # Echo Reply -> Destination reached
                    break

            except timeout:
                times.append("*")
            finally:
                mySocket.close()

        # Output hop
        times_str = "   ".join(t if t != "*" else "*" for t in times)
        if addr:
            try:
                host_name = gethostbyaddr(addr)[0]
                print(f"{ttl:<3} {times_str:<25} {host_name} [{addr}]")
            except herror:
                print(f"{ttl:<3} {times_str:<25} {addr}")
        else:
            print(f"{ttl:<3} {'   '.join('*' for _ in range(TRIES))}   Request timed out.")

        if addr == gethostbyname(hostname):
            break

    print("\nTrace complete.")


if __name__ == "__main__":
    targets = ["google.com", "dlsu.instructure.com", "dlsu.edu.ph"]
    for host in targets:
        get_route(host)
