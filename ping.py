# Things to imrpove and add: Logging system, smoother program failure, support multiple type of input, more customizable inputs with their defaults, function seperation


import scapy.all as scapy
import time as time
import argparse as argparse
import socket as socket


# For inputed IP error handling
def ip_eh(ip):
    try:
        ip = socket.gethostbyname(ip)
        return ip
    except socket.gaierror:
        return False


# Create a Packet
def cpkt(ip, TTL):
    return scapy.IP(dst=ip, ttl=TTL) / scapy.ICMP()


# Receive Response and return response + ms
def sr_and_measure(pkt):
    start = time.perf_counter()
    response = scapy.sr1(pkt, timeout=2, verbose=0)
    end = time.perf_counter()

    if response:
        ms = int((end - start) * 1000)
        return response, ms
    else:
        return None, None


# RTTS calculation of avg, min, max
def rttcal(rttslist):

    if rttslist:

        avg_rtt = int(sum(rttslist) / len(rttslist))
        min_rtt = min(rttslist)
        max_rtt = max(rttslist)
    else:
        avg_rtt = min_rtt = max_rtt = 0

    return avg_rtt, min_rtt, max_rtt


def ping(ip, ttlpkt, TTL):
    sent = 0
    receive = 0
    lost = 0
    rttslist = []
    for seq in range(1, ttlpkt + 1):
        time.sleep(1)
        response, ms = sr_and_measure(cpkt(ip, TTL))

        sent += 1

        if response:
            receive += 1
            rec_ttl = response.ttl

            print(f"Reply from {ip}: seq={seq}, TTL={rec_ttl}, time={ms}ms")

            rttslist.append(ms)

        else:
            print("Request timed out")
            lost += 1

    avg_rtt, min_rtt, max_rtt = rttcal(rttslist)

    print("---Ping statistics---")
    print(f"Packet: Sent={sent}, Receive={receive}, Lost={lost}")
    print(f"RTT: Min={min_rtt}ms, Max={max_rtt}ms, Avg={avg_rtt}ms")


parser = argparse.ArgumentParser(description="IP address and total packets")
parser.add_argument("ip", help="Add IP Address to ping")
parser.add_argument("-p", "--packet", default=4, help="Number of packets to send")
parser.add_argument("-t", "--ttl", default=64, help="TTL")

args = parser.parse_args()

ttlpkt = int(args.packet)
ttl = int(args.ttl)
ip_check = ip_eh(args.ip)

if ip_check:
    ping(ip_check, ttlpkt, ttl)

else:
    print("Invalid IP, Please check the spell")
