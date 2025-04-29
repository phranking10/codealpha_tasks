from scapy.all import *

# List all available network interfaces
print("Available network interfaces:")
print(get_if_list())

# Explicitly set the default interface to use Npcap
conf.iface = "Wi-Fi"  # Replace with your network interface name
conf.use_pcap = True  # Force scapy to use pcap (Npcap)

# Print the current configuration to verify
print(f"Using interface: {conf.iface}")
print(f"Using pcap: {conf.use_pcap}")

# Define a callback function to process each packet
def process_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src  # Source IP address
        ip_dst = packet[IP].dst  # Destination IP address

        print(f"Source IP: {ip_src} -> Destination IP: {ip_dst}")

        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"TCP Port: {tcp_layer.sport} -> {tcp_layer.dport}")

        # Check if the packet has a UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"UDP Port: {udp_layer.sport} -> {udp_layer.dport}")

# Start sniffing the network
def start_sniffing(interface=None, filter_str=None):
    print("Starting network sniffer...")

    # Sniff the network traffic
    sniff(iface=interface, prn=process_packet, filter=filter_str, store=False)

if __name__ == "__main__":
    # Specify the network interface to sniff on (None means all interfaces)
    interface = "Wi-Fi"  # Replace with your actual interface name

    # Optional: BPF filter string to capture only certain types of traffic
    # Example: 'tcp' to capture only TCP traffic, 'udp port 53' to capture DNS traffic
    filter_str = "tcp"

    # Start sniffing
    start_sniffing(interface=interface, filter_str=filter_str)

    print("Debugging complete.")