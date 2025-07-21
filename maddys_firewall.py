from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.inet import TCP, UDP, IP, ICMP

# tracks scan counts & timestamps
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})

# define duration to block an IP
BLOCK_DURATION = timedelta(minutes=10)

def is_ip_blocked(ip):
    result = subprocess.run(["sudo", "iptables", "-L", "-n"], stdout=subprocess.PIPE, text=True)
    return ip in result.stdout

def block_ip(ip):
    if is_ip_blocked(ip):
        print("ip is already blocked")
        return
    else:
        print(f"blocking ip: {ip}")
        try: 
            subprocess.run(["sudo", "iptables", '-A', 'INPUT', '-s', f'{ip}', '-j', 'DROP'], check=True)
        except subprocess.CalledProcessError as e:
            print(f"error blocking IP {ip}: {e}")

def unblock_ip(ip):
    print(f"unblocking ip: {ip}")

    try: 
        subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"unable to unblock ip {ip}: {e}")

def handle_packet(packet):
    if TCP in packet and packet[TCP].flags == "S": #this means the packet has a SYN flag 
        src_ip = packet[IP].src
        port=packet[TCP].dport
        src_port = packet[TCP].sport

        print(f"scan detected on port {port} from {src_ip}")

        # check and update scan count
        current_time = datetime.now()

        if scan_tracker[src_ip]["timestamp"] and current_time - scan_tracker[src_ip]["timestamp"] > BLOCK_DURATION:
            # reset tracker after block duration
            scan_tracker[src_ip] = {"count": 0, "timestamp": None}

        scan_tracker[src_ip][src_ip]["count"] += 1
        scan_tracker[src_ip]["timestamp"] = current_time

        if scan_tracker[src_ip]["count"] > 5:
            print(f"IP {src_ip} exceeded scan limit, blocking for 10 minutes")
            block_ip(src_ip)
            #scheduling the unblocking
            unblock_time = datetime.now() + BLOCK_DURATION
            print(f"IP {src_ip} will be unblocked at {unblock_time.strftime('%Y-%m-%d %H:%M:%S')}")
            sniff_thread.unblock_tasks.append({"ip": src_ip, "unblock_time": unblock_time})
            return

        # respond with SYN-ACK
        syn_ack = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=port, dport=src_port, flags="SA", seq=100, ack=packet[TCP].seq + 1)
        )

        send(syn_ack, verbose=0)
        print(f"sent SYN-ACK to {src_ip} on port {port}")

        # send a message in a follow up data packet
        data_packet = (
            IP(dst=src_ip, src=packet[IP].dst) /
            TCP(sport=port, dport=src_port, flags="PA", seq=101, ack=packet[TCP].seq + 1) /
            Raw(load="try harder")
        )
        
        send(data_packet, verbose=0)
        print(f"send data packet with message 'try harder' to {src_ip} on port {port}")

def unblock_expired_ips():
    now = datetime.now()
    for unblock_task in list(sniff_thread.unblock_tasks):
        if now >= unblock_task["unblock_time"]:
            unblock_ip(unblock_task["ip"])
            sniff_thread.unblock_tasks.remove(unblock_task)

class SniffThread:
    def __init__(self):
        self.unblock_tasks = []

    def start_sniffing(self):
        sniff(filter="tcp", prn=handle_packet)

sniff_threat = SniffThread()


if __name__ == "__main__":
    import threading

    # start the sniffing in a separate thread

    sniff_thread = SniffThread()
    sniff_thread_thread = threading.Thread(target=sniff_thread.start_sniffing, daemon=True)
    sniff_thread_thread.start()

    # monitor unblock tasks in the main thread
    try:
        while True:
            unblock_expired_ips()
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping...")



