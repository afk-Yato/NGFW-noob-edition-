
from scapy.all import sniff, IP, IPv6, ARP, TCP, UDP, ICMP
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import os, sys
import json

#switch between w monitoring or w/
VERBOSE = True

PACKET_WINDOW = 10              #only analyzing the packets from 10s from now
PORT_SCAN_THRESHOLD = 50        # 50 dest ports per src in 10 sec , port scan detection 
SYN_FLOOD_SYN_THRESHOLD = 100   #SYNs per src , Dos detection
SYN_ACK_RATIO = 0.1             #SYN/ACK , wierd connections
ICMP_FLOOD_THRESHOLD = 80       #ICMP echo requests per source , ping floods detection

packet_history = defaultdict(lambda: {
    "times": deque(),
    "dst_ports": Counter(),
    "syn_times": deque(),
    "ack_times": deque(),
    "icmp_times": deque()
})

#just for loggins to detect attack 
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "alerts.json")


def now():
    return datetime.now()


def prune_old_packets(src):
    
    cutoff = now() - timedelta(seconds=PACKET_WINDOW)
    info = packet_history[src]

    info["times"] = deque([t for t in info["times"] if t >= cutoff])
    info["syn_times"] = deque([t for t in info["syn_times"] if t >= cutoff])
    info["ack_times"] = deque([t for t in info["ack_times"] if t >= cutoff])
    info["icmp_times"] = deque([t for t in info["icmp_times"] if t >= cutoff])

    # Drop old ports (we don't timestamp ports here, but remove zero-count entries)
    for port in list(info["dst_ports"]):
        if info["dst_ports"][port] <= 0:
            del info["dst_ports"][port]


def analyze_packets(packet):
    try:
        # if it's not IPv4, try IPv6 or ARP; handle non-IP safely
        if ARP in packet:
            # print ARP summary and return
            if VERBOSE:
                print(f"[non IP packet - ARP] : {packet.summary()}")
            return

        # prefer IPv4, fallback to IPv6
        src = dst = protocol = None
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            protocol = packet[IP].proto
        elif IPv6 in packet:
            src = packet[IPv6].src
            dst = packet[IPv6].dst
            # IPv6 next header number isn't always needed below; leave protocol as None for v6
            protocol = None
        else:
            # non-IP (Ethernet-only, IPv6 without IPv6 layer handled above, etc.)
            if VERBOSE:
                print(f"[non IP packet] : {packet.summary()} ")
            return

        timestamp = now()

        info = packet_history[src]  # get IP record or create if new 
        info["times"].append(timestamp)  # storing ip time

        #parsing TCP packets
        if TCP in packet:
            tcp = packet[TCP]
            sport = tcp.sport
            dport = tcp.dport
            flags = tcp.flags

            info["dst_ports"][dport] += 1  # count destination ports ; how many req sent to a unique port

            if flags & 0x02:  # check if second bit of the tcp flag is on (SYN flag)  
                info["syn_times"].append(timestamp)
            if flags & 0x10:  # for ack flag
                info["ack_times"].append(timestamp)

            if VERBOSE:
                print(f"[TCP] {src} : {sport} -> {dst} : {dport} | Flags = {flags}")

        #parsing UDP packets
        elif UDP in packet:
            udp = packet[UDP]
            sport = udp.sport
            dport = udp.dport
            info["dst_ports"][dport] += 1  # count destination ports ; how many req sent to a unique port

            if VERBOSE:
                print(f"[UDP] {src} : {sport} -> {dst} : {dport} ")

        #ICMP
        elif ICMP in packet:
            info["icmp_times"].append(timestamp)

            if VERBOSE:
                print(f"[ICMP] {src} -> {dst}")

        # Cleanup old data (keep only last PACKET_WINDOW seconds)
        prune_old_packets(src)

        # --- Run detection rules for this source ---
        # check port scan
        try:
            alert = prot_scan_rules(src)
            if alert:
                alert["confidence"] = "medium"
                log_alerts(alert)
                print("[ALERT]", alert)
                # optional: clear counters or add cooldown here
        except Exception as e:
            print("[!] prot_scan_rules error:", e)

        # check syn flood
        try:
            alert = syn_flood_rules(src)
            if alert:
                alert["confidence"] = "medium"
                log_alerts(alert)
                print("[ALERT]", alert)
        except Exception as e:
            print("[!] syn_flood_rules error:", e)

        # check icmp flood
        try:
            alert = icmp_flood(src)
            if alert:
                alert["confidence"] = "medium"
                log_alerts(alert)
                print("[ALERT]", alert)
        except Exception as e:
            print("[!] icmp_flood error:", e)

    except Exception as e:
        # never crash the sniffer; print safe debug info
        print(f"[!] error parsing the packet {e}")
        try:
            print(packet.summary())
        except Exception:
            pass




def log_alerts(alert):
    alert["time"]=now().isoformat() #make time in ISO format

    try:
        with open(LOG_FILE,"a") as f:
            f.write(json.dumps(alert)+"\n")
            
    except Exception as e:
        print("[!] Failed to log the alert : ",e)
        print(alert)


def prot_scan_rules(src):
    info = packet_history[src]

    unique_ports = len(info["dst_ports"])
    
    if unique_ports >= PORT_SCAN_THRESHOLD:
        alert = {
                "type" : "port_scan",
                "src" : src,
                "unique_dst_ports" : unique_ports,
                "threshold" : PORT_SCAN_THRESHOLD,
                "note" : f"{unique_ports} unique destinqtion ports in last {PACKET_WINDOW}"
                }
        return alert
    return None # if there is a scan return alert if not ret none

def syn_flood_rules(src):
    info = packet_history[src]

    syn_count = len(info["syn_times"])
    ack_count = len(info["ack_times"])
    ratio = (ack_count / syn_count) if syn_count > 0 else 1.0
    if (syn_count >= SYN_FLOOD_SYN_THRESHOLD) and (ratio < SYN_ACK_RATIO):
        alert ={
                "type" : "syn_flood",
                "src" : src ,
                "syn_count" : syn_count,
                "ack_count" : ack_count,
                "syn_threshold" : SYN_FLOOD_SYN_THRESHOLD ,
                "current_ratio" : ratio,
                "treshold_ratio" : SYN_ACK_RATIO,
                "note" : f"{syn_count} SYN and {ack_count} with a ratio of {ratio:.3f} in {PACKET_WINDOW}"
                }
        return alert
    return None

def icmp_flood(src):
    info = packet_history[src]

    icmp_count = len(info["icmp_times"])

    if icmp_count >= ICMP_FLOOD_THRESHOLD:
        alert={
            "type" : "icmp_flood",
            "src": src,
            "icmp_count" : icmp_count,
            "icmp_threshold" : ICMP_FLOOD_THRESHOLD,
            "note" : f"{icmp_count} ICMP echo requests in {PACKET_WINDOW}"
              }
        return alert
    return None



if __name__ == "__main__":
    # quick fail if not root
    if os.geteuid() != 0:
        sys.exit("This script requires root")
    INTERFACE = "eth0"  
    print(f"Sniffing on {INTERFACE} (verbose={VERBOSE}) - press Ctrl-C to stop")
    sniff(iface=INTERFACE, prn=analyze_packets, store=False)

