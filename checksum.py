from scapy.all import *
import sys
import os
def validate_checksums(pcap_file):
    try:
        print(f"[*] Loading {pcap_file}...")
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: File {pcap_file} not found.")
        return
    print(f"[*] Analyzing {len(packets)} packets...\n")
    print(f"{'Packet #':<10} | {'Protocol':<10} | {'Status':<10} | {'Original':<10} | {'Calculated':<10}")
    print("-" * 65)
    for i, pkt in enumerate(packets):
        packet_num = i + 1    
        # --- Layer 3: IP Checksum Validation ---
        if IP in pkt:
            proto_name = "IP"
            original_chksum = pkt[IP].chksum
            
            # Recalculate IP Checksum
            temp_pkt = pkt.copy()
            del temp_pkt[IP].chksum
            temp_pkt = IP(raw(temp_pkt[IP])) 
            calc_chksum = temp_pkt.chksum
            
            match = original_chksum == calc_chksum
            status = "VALID" if match else "INVALID"
            print(f"{packet_num:<10} | {proto_name:<10} | {status:<10} | {hex(original_chksum):<10} | {hex(calc_chksum):<10}")

        # --- Layer 4: TCP / UDP / ICMP Checksum Validation ---
        l4_layer = None
        if TCP in pkt:
            l4_layer = TCP
            proto_name = "TCP (TLS)" if pkt[TCP].dport == 443 or pkt[TCP].sport == 443 else "TCP"
        elif UDP in pkt:
            l4_layer = UDP
            proto_name = "UDP"
        elif ICMP in pkt:
            l4_layer = ICMP
            proto_name = "ICMP"

        if l4_layer:
            original_chksum = pkt[l4_layer].chksum
            
            # Recalculate Layer 4 Checksum
            temp_pkt = pkt.copy()
            del temp_pkt[l4_layer].chksum
            
            # Force recalculation by refreshing the packet raw bytes
            # This handles the Pseudo-header automatically via Scapy
            temp_pkt = temp_pkt.__class__(raw(temp_pkt))          
            calc_chksum = temp_pkt[l4_layer].chksum

            match = original_chksum == calc_chksum
            status = "VALID" if match else "INVALID"   
            print(f"{packet_num:<10} | {proto_name:<10} | {status:<10} | {hex(original_chksum):<10} | {hex(calc_chksum):<10}")

if __name__ == "__main__":
    # Ensure this filename matches your actual Wireshark save file
    pcap_filename = "cap_files.pcap.pcapng" 
    
    if not os.path.exists(pcap_filename):
        print("Creating dummy pcap for demonstration...")
        dummy_pkts = [
            IP(dst="8.8.8.8")/TCP(), 
            IP(dst="1.1.1.1")/UDP(), 
            IP(dst="8.8.8.8")/ICMP()
        ]
        wrpcap(pcap_filename, dummy_pkts)
    validate_checksums(pcap_filename)
