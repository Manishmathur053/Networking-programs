import scapy.all as scapy
from scapy.all import ICMP
import time
import argparse
import socket


# For inputed IP error handling
def resolve_ip(ip):
    try:
        ip = socket.gethostbyname(ip)
        return ip
    except socket.gaierror:
        return False


# Create a Packet
def create_packet(ip, TTL):
    return scapy.IP(dst=ip, ttl=TTL) / scapy.ICMP()


# Receive Response and return response + ms
def send_and_analyze(pkt):
    start = time.perf_counter()
    response = scapy.sr1(pkt, timeout=2, verbose=0)
    end = time.perf_counter()

    if not response:
        return "drop", None, None

    if not response.haslayer(ICMP):
        return "non_icmp", None, None
    else:
        icmp = response[ICMP]

    if icmp.type == 0:
        ms = int((end - start) * 1000)
        rec_ttl = response.ttl
        return "success", ms, rec_ttl

    elif icmp.type == 3:

        if icmp.code == 0:
            return "net_unreachable", None, None

        elif icmp.code == 1:

            return "host_unreachable", None, None
        elif icmp.code == 3:

            return "port_unreachable", None, None
        else:
            return "unknown", None, None
    else:

        return "unknown", None, None


# RTTS calculation of avg, min, max
def rttcalculation(rttslist):

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
        status, ms, rec_ttl = send_and_analyze(create_packet(ip, TTL))

        sent += 1

        if status == "success":
            receive += 1

            print(f"Reply from {ip}: seq={seq}, TTL={rec_ttl}, time={ms}ms")

            rttslist.append(ms)

        else:
            receive += 1
            if status == "net_unreachable":
                print("Destination route unreachable")
            elif status == "host_unreachable":
                print("Host Unreachable")
            elif status == "port_unreachable":
                print("Port Unreachable")
            elif status == "unknown":
                print("Unknown issue")
            elif status == "drop":
                lost += 1
                receive -= 1
                print("No response (filtered / dropped)")
            elif status == "non_icmp":
                print("Non ICMP layer response")

    avg_rtt, min_rtt, max_rtt = rttcalculation(rttslist)

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
ip_check = resolve_ip(args.ip)

if ip_check:
    ping(ip_check, ttlpkt, ttl)

else:
    print("Invalid IP, Please check the spell")
