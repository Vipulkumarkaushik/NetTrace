"""
NetTrace Protocol Analyzer
Captures and analyzes 802.11 (Wi-Fi) and TCP/UDP network traffic.
Generates system logs for root-cause failure triage and performance monitoring.
"""

from scapy.all import sniff
import logging
import sys

# Configure structured system logging for automated parsing
logging.basicConfig(
    filename='network_triage.log', 
    level=logging.INFO, 
    format='%(asctime)s | %(levelname)s | %(message)s'
)

def process_packet(packet):
    """
    Callback function to dissect network packets.
    Inspects layers for 802.11 or IP protocols and logs the traces.
    """
    try:
        # Check for 802.11 Wi-Fi Protocol layer
        if packet.haslayer('Dot11'):
            log_msg = f"802.11 Wi-Fi Frame Captured: {packet.summary()}"
            logging.info(log_msg)
            print(f"[+] {log_msg}")
            
        # Fallback to standard IP layer for TCP/UDP traffic
        elif packet.haslayer('IP'):
            src_ip = packet['IP'].src
            dst_ip = packet['IP'].dst
            protocol = packet['IP'].proto
            log_msg = f"IP Traffic (Proto {protocol}): {src_ip} -> {dst_ip}"
            logging.info(log_msg)
            print(f"[*] {log_msg}")
            
    except Exception as e:
        # Log parsing errors for failure triage
        error_msg = f"Packet Dissection Error: {str(e)}"
        logging.error(error_msg)
        print(f"[-] {error_msg}")

def start_capture(interface="Wi-Fi", count=50):
    """
    Initializes the Scapy sniffer on the specified network interface.
    """
    print(f"Starting NetTrace capture on interface: {interface}...")
    logging.info(f"Capture session initialized on {interface} for {count} packets.")
    
    # Sniff network traffic without storing in memory (store=0) for performance
    # Live capture ki jagah pcap file read karne ke liye offline argument use kar
    sniff(offline="sample_traffic.pcap", prn=process_packet, store=0)
    
    print("Capture session completed. Traces saved to network_triage.log")
    logging.info("Capture session terminated successfully.")

if __name__ == "__main__":
    # Allow passing interface name via command line arguments
    target_iface = sys.argv[1] if len(sys.argv) > 1 else "Wi-Fi"
    start_capture(interface=target_iface, count=20)
