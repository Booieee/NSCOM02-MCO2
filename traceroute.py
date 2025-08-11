# NSCOM02 - MC02
# Members:
# De Jesus, Andrei Zarmin D.
# Sayat, John Christian N.

from socket import *
import os
import sys
import struct
import time
import select
import requests

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 30
TIMEOUT = 2.0
TRIES = 2
REQUEST_DELAY = 1.5

error_msg = {
    0: "Network Unreachable",
    1: "Host Unreachable",
    2: "Protocol Unreachable",
    3: "Port Unreachable",
    4: "Fragmentation Needed",
    5: "Source Route Failed",
}

def get_geoloc(ip_addr):
    if ip_addr == "*" or ip_addr.startswith("192.168.") or ip_addr.startswith("10.") or ip_addr.startswith("172."):
        return "      (Private/Local IP)"
    
    try:
        url = f"http://ip-api.com/json/{ip_addr}?fields=status,message,country,regionName,city,org,isp"
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data['status'] == 'success':
            city = data.get('city', 'Unknown')
            region = data.get('regionName', 'Unknown')
            country = data.get('country', 'Unknown')
            org = data.get('org', 'Unknown')
            isp = data.get('isp', 'Unknown')

            location = []
            if city != 'Unknown' and city:
                location.append(f"City: {city}")
            if region != 'Unknown' and region:
                location.append(f"Region: {region}")
            if country != 'Unknown' and country:
                location.append(f"Country: {country}")
            if org != 'Unknown' and org:
                location.append(f"Organization: {org}")

            if location:
                return "    " + " | ".join(location)
            else:
                return "     Geolocation data not available"
        else:
            return f"     Geolocation error: {data.get('message', 'Unknown error')}"
        
    except Exception as e:
        return f"     Geolocation error: {str(e)}"

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
    
    print(f"\nTraceroute to {hostname} ({destAddr}), {MAX_HOPS} hops max:")
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

                if whatReady[0] == []: 
                    if tries == TRIES - 1:  
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
                    geo_info = get_geoloc(addr[0])
                    print(geo_info)
                    hop_found = True
                    time.sleep(REQUEST_DELAY)

                elif types == 3:
                    error_code = error_msg.get(code, f"Unknown code {code}")
                    print(f"{ttl:<5} {addr[0] + f' (Destination Unreachable: {error_code})':<50} {rtt_ping:<10}")
                    geo_info = get_geoloc(addr[0])
                    print(geo_info)
                    hop_found = True
                    return True  
                    
                elif types == 0:
                    print(f"{ttl:<5} {addr[0] + ' (Echo Reply - Destination Reached)':<50} {rtt_ping:<10}")
                    geo_info = get_geoloc(addr[0])
                    print(geo_info)
                    hop_found = True
                    return True  
                    
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
    hostnames = ["google.com", "dlsu.instructure.com", "dlsu.edu.ph", "my.dlsu.edu.ph"]

    for target in hostnames:
        try:
            completed = get_route(target)
            if completed:
                print("Traceroute completed successfully!")
            else:
                print(f"Traceroute reached maximum hops ({MAX_HOPS}) without reaching destination.")
        except Exception as e:
            print(f"Error during traceroute to {target}: {e}")
        
        print("\n" + "=" * 80 + "\n")



# to-do
# 1. Change to input after testing
# 2. debug api part
# 3. remove debug comments

