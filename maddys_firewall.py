from scapy.all import *
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from scapy.layers.inet import TCP, UDP, IP, ICMP
from dotenv import load_dotenv
import requests
import json
import time
import os



# tracks scan counts & timestamps
scan_tracker = defaultdict(lambda: {"count": 0, "timestamp": None})
# abuseipdb threat cache
threat_cache = {}
CACHE_DURATION = timedelta(hours=24)


# configuring settings

# define duration to block an IP
BLOCK_DURATION = timedelta(minutes=10)
# AbuseIPDB API Key variable
load_dotenv()
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY_1")
# define threshold of abuse confidence to block
THREAT_THRESHOLD = 25
# define threshold of abuse confidence to immediately block
HIGH_THREAT_THRESHOLD = 75

def check_ip_threat(ip):
    if ip in threat_cache:
        cached_data = threat_cache[ip]
        if datetime.now() - cached_data["timestamp"] < CACHE_DURATION:
            return cached_data["data"]
    
    # query abuseipdb api
    try:
        url = "https://api.abuseipdb.com/api/v2/check"

        querystring = {
            'ipAddress' : ip,
        }

        headers = {
            'Accept': 'application/json',
            'Key': ABUSE_IPDB_API_KEY
        }

        response = requests.request(method='GET', url=url, headers=headers, params=querystring)

        if response.status_code == 200:
            data = response.json()['data']

            # cache the result
            threat_cache[ip] = {
                'data': data,
                'timestamp': datetime.now()                
            }
            print(f"successful query for ip: {ip}")
            return data
        else:
            print(f"AbuseIPDB error for {ip}: {response.status_code}")
            return None
    except requests.RequestException as e:
        print(f"error querying AbuseIPDB for {ip}: {e}")
        return None
    
def analyze_threat_level(threat_data):
    if not threat_data:
        return "unknown", 0
    
    confidence = threat_data.get('abuseConfidencePercentage', 0)
    usage = threat_data.get('usageType', 'unknown')
    country = threat_data.get('countryCode', 'unknown')

    print(f'Threat info: Confidence={confidence}, Usage Type: {usage}, Country: {country}')

    if confidence >= HIGH_THREAT_THRESHOLD:
        return "high_threat", confidence
    elif confidence >= THREAT_THRESHOLD:
        return "medium_threat", confidence
    else:
        return "low_threat", confidence
    
def is_ip_blocked(ip):
    # run the linux command for grabbing all packet dropping rules
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

        scan_tracker[src_ip]["count"] += 1
        scan_tracker[src_ip]["timestamp"] = current_time


        # checks IP address against list of known malicious IPs
        ip_threat_data = check_ip_threat(src_ip)
        threat_level, confidence = analyze_threat_level(ip_threat_data)
        if threat_level == "high_threat":
            print(f"this is considered an ip with a high threat level, blocking {src_ip} immediately")
            block_ip(src_ip)
            return

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

def cleanup_cache():
    now = datetime.now()

    expired_ips = [ip for ip, data in threat_cache.items()
                    if now - data["timestamp"] > CACHE_DURATION]
    
    for ip in expired_ips:
        del threat_cache[ip]
    
    if expired_ips:
        print(f"cleaned up {len(expired_ips)} expired cache entries")

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
        cache_cleanup_counter = 0
        while True:
            unblock_expired_ips()
            cache_cleanup_counter += 1
            if cache_cleanup_counter >= 720:
                cleanup_cache()
                cache_cleanup_counter = 0
            time.sleep(5)
    except KeyboardInterrupt:
        print("\nStopping...")
        print(f"Final cache size: {len(threat_cache)}")
