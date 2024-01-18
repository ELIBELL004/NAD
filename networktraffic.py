import scapy.all as scapy
from collections import Counter

def capture_packets(interface, count=100):
    """Captures a specified number of packets from the given interface."""
    packets = scapy.sniff(iface=interface, count=count)
    return packets

def analyze_packets(packets):
    """Analyzes captured packets to extract key information."""
    ip_counts = Counter()
    protocol_counts = Counter()
    port_counts = Counter()

    for packet in packets:
        if packet.haslayer(scapy.IP):
            ip_counts[packet[scapy.IP].src] += 1
            protocol_counts[packet[scapy.IP].proto] += 1
            if packet.haslayer(scapy.TCP) or packet.haslayer(scapy.UDP):
                port_counts[packet[scapy.TCP].dport] += 1  # Or UDP.dport

    return ip_counts, protocol_counts, port_counts

def detect_anomalies(ip_counts, protocol_counts, port_counts):
    """Detects potential anomalies based on analysis results."""
    anomalies = []

    # Example anomaly detection rules (replace with your specific logic):
    for ip, count in ip_counts.items():
        if count > 50:  # Flag IPs with frequent activity
            anomalies.append(f"High activity from IP: {ip}")

    # Add more rules for protocol and port anomalies as needed

    return anomalies

def main():
    interface = "eth0"  # Replace with your interface name
    packets = capture_packets(interface)
    ip_counts, protocol_counts, port_counts = analyze_packets(packets)
    anomalies = detect_anomalies(ip_counts, protocol_counts, port_counts)

    # Print analysis results and anomalies
    print("IP Counts:\n", ip_counts)
    print("Protocol Counts:\n", protocol_counts)
    print("Port Counts:\n", port_counts)
    print("Detected Anomalies:\n", anomalies)

if __name__ == "__main__":
    main()

def detect_anomalies(ip_counts, protocol_counts, port_counts):
    """Detects potential anomalies using a wider range of rules and thresholds."""
    anomalies = []

    # IP-based anomalies:
    for ip, count in ip_counts.items():
        if count > 100:  # Flag IPs with very high activity
            anomalies.append(f"Very high activity from IP: {ip}")
        elif count > 50 and ip not in internal_ips:  # Flag external IPs with moderate activity
            anomalies.append(f"Moderate activity from external IP: {ip}")

    # Protocol-based anomalies:
    for protocol, count in protocol_counts.items():
        if protocol in ["TCP", "UDP"] and count > 400:  # Flag high TCP or UDP traffic
            anomalies.append(f"High {protocol} traffic")
        elif protocol in ["ICMP", "ARP"] and count > 50:  # Flag unusual ICMP or ARP activity
            anomalies.append(f"Unusual {protocol} activity")

    # Port-based anomalies:
    for port, count in port_counts.items():
        if port in common_attack_ports and count > 10:  # Flag activity on common attack ports
            anomalies.append(f"Activity on common attack port: {port}")

    # Additional rules:
    # - Detect sudden spikes in traffic volume
    # - Identify unusual packet sizes or patterns
    # - Flag specific protocol combinations (e.g., TCP SYN floods)
    # - Use statistical techniques for outlier detection

    return anomalies 
