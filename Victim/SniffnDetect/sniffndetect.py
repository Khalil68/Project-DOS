import os  # Provides a way to use operating system dependent functionality
import sys  # Provides access to system-specific parameters and functions
import csv  # Used to read and write CSV files
import ctypes  # Allows calling functions in DLLs or shared libraries
import threading  # Provides thread support to run tasks in parallel
from scapy.all import *  # Imports all features from the Scapy library, which is used for packet manipulation
from queue import Queue  # Provides a thread-safe queue for communication between threads

class SniffnDetect():
    def __init__(self):
        self.INTERFACE = conf.iface  # Gets the network interface being used
        # Retrieves the IP address associated with the network interface
        self.MY_IP = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0' and x[3] == self.INTERFACE][0]
        self.MY_MAC = get_if_hwaddr(self.INTERFACE)  # Gets the MAC address of the interface
        self.WEBSOCKET = None  # Placeholder for a WebSocket connection (not used in the code provided)
        self.PACKETS_QUEUE = Queue()  # Creates a queue to hold packets for processing
        self.MAC_TABLE = {}  # Dictionary to keep track of MAC addresses and their associated IPs
        self.RECENT_ACTIVITIES = []  # List to store recent activities
        # Dictionary to filter and store detected attack activities
        self.FILTERED_ACTIVITIES = {
            'TCP-SYN': {'flag': False, 'activities': [], 'attacker-mac': []},
            'TCP-SYNACK': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-POD': {'flag': False, 'activities': [], 'attacker-mac': []},
            'ICMP-SMURF': {'flag': False, 'activities': [], 'attacker-mac': []},
        }
        self.flag = False  # Flag to control the start/stop of sniffing

        # Open a CSV file to log attacks, create it if it doesn't exist
        self.csv_file = open('ddos_attack_logs.csv', 'a', newline='')
        self.csv_writer = csv.writer(self.csv_file)  # Create a CSV writer object
        # Write the header for the CSV file
        self.csv_writer.writerow(['Timestamp', 'Source_IP', 'Destination_IP', 'Attack_Type', 'Packet_Size'])

    def sniffer_threader(self):
        # This function runs in a separate thread to sniff packets
        while self.flag:  # Run while the sniffing flag is True
            pkt = sniff(count=1)  # Capture one packet
            with threading.Lock():  # Ensure thread-safe access to the queue
                self.PACKETS_QUEUE.put(pkt[0])  # Add the captured packet to the queue

    def analyze_threader(self):
        # This function runs in a separate thread to analyze packets
        while self.flag:  # Run while the sniffing flag is True
            pkt = self.PACKETS_QUEUE.get()  # Get a packet from the queue
            self.analyze_packet(pkt)  # Analyze the packet
            self.PACKETS_QUEUE.task_done()  # Indicate that the packet has been processed

    def check_avg_time(self, activities):
        # Check if the average time between recent activities is below a threshold
        if len(activities) < 2:  # We need at least 2 activities to compare
            return False

        time_total = 0  # Total time between activities
        count = 0  # Count of activities processed

        # Only process up to the last 30 activities
        for i in range(1, min(30, len(activities))):
            # Calculate the time difference between the last two activities
            time_total += activities[-i][0] - activities[-(i+1)][0]
            count += 1

        # Calculate the average time
        avg_time = time_total / count if count > 0 else float('inf')

        # Check if the average time is less than 2 seconds and the last activity was within 10 seconds
        return avg_time < 2 and (self.RECENT_ACTIVITIES[-1][0] - activities[-1][0] < 10)

    def find_attackers(self, category):
        # Find attackers for a given category of attack
        data = []
        for mac in self.FILTERED_ACTIVITIES[category]['attacker-mac']:
            # Check if the MAC address is known; if not, label it as Unknown IP
            data.append(
                f"({self.MAC_TABLE[mac]}, {mac})" if mac in self.MAC_TABLE else f"(Unknown IP, {mac})"
            )
        # Return a formatted string of attackers for that category
        return category + ' Attackers :<br>' + "<br>".join(data) + '<br><br>'

    def set_flags(self):
        # Set flags for each attack category based on activity analysis
        for category in self.FILTERED_ACTIVITIES:
            activities = self.FILTERED_ACTIVITIES[category]['activities']
            # Check if there are enough activities (more than 2)
            if len(activities) > 2:
                self.FILTERED_ACTIVITIES[category]['flag'] = self.check_avg_time(activities)
                if self.FILTERED_ACTIVITIES[category]['flag']:
                    # Get unique MAC addresses of attackers
                    self.FILTERED_ACTIVITIES[category]['attacker-mac'] = list(
                        set([i[3] for i in activities if len(i) > 3])
                    )

    def analyze_packet(self, pkt):
        # Analyze a given packet for attack detection
        src_ip, dst_ip, src_port, dst_port, tcp_flags, icmp_type = None, None, None, None, None, None
        protocol = []  # List to keep track of protocols used in the packet

        # Keep only the last 15 recent activities
        if len(self.RECENT_ACTIVITIES) > 15:
            self.RECENT_ACTIVITIES = self.RECENT_ACTIVITIES[-15:]

        # Keep only the last 30 activities for each attack category
        for category in self.FILTERED_ACTIVITIES:
            if len(self.FILTERED_ACTIVITIES[category]['activities']) > 30:
                self.FILTERED_ACTIVITIES[category]['activities'] = self.FILTERED_ACTIVITIES[category]['activities'][-30:]

        self.set_flags()  # Update flags based on the current activities

        # Extract source and destination MAC addresses
        src_mac = pkt[Ether].src if Ether in pkt else None
        dst_mac = pkt[Ether].dst if Ether in pkt else None

        # Check if the packet is using IPv4 or IPv6
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

        # Check if the packet is using TCP, UDP, or ICMP
        if TCP in pkt:
            protocol.append("TCP")  # Add TCP to the protocol list
            src_port = pkt[TCP].sport  # Source port
            dst_port = pkt[TCP].dport  # Destination port
            tcp_flags = pkt[TCP].flags.flagrepr()  # TCP flags
        if UDP in pkt:
            protocol.append("UDP")  # Add UDP to the protocol list
            src_port = pkt[UDP].sport  # Source port
            dst_port = pkt[UDP].dport  # Destination port
        if ICMP in pkt:
            protocol.append("ICMP")  # Add ICMP to the protocol list
            icmp_type = pkt[ICMP].type  # ICMP type

        # Handle ARP packets
        if ARP in pkt and pkt[ARP].op in (1, 2):
            protocol.append("ARP")  # Add ARP to the protocol list
            # Update the MAC_TABLE with the source MAC and IP
            if pkt[ARP].hwsrc in self.MAC_TABLE.keys() and self.MAC_TABLE[pkt[ARP].hwsrc] != pkt[ARP].psrc:
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc
            if pkt[ARP].hwsrc not in self.MAC_TABLE.keys():
                self.MAC_TABLE[pkt[ARP].hwsrc] = pkt[ARP].psrc

        load_len = len(pkt[Raw].load) if Raw in pkt else None  # Length of the packet load if it exists

        attack_type = None  # To hold the type of attack detected

        # Analyze for specific types of attacks
        if ICMP in pkt:
            if src_ip == self.MY_IP and src_mac != self.MY_MAC:  # Check for ICMP-SMURF attack
                self.FILTERED_ACTIVITIES['ICMP-SMURF']['activities'].append([pkt.time, ])
                attack_type = 'ICMP-SMURF PACKET'

            if load_len and load_len > 1024:  # Check for ICMP-PoD attack
                self.FILTERED_ACTIVITIES['ICMP-POD']['activities'].append([pkt.time, ])
                attack_type = 'ICMP-PoD PACKET'

        # Analyze TCP packets for SYN and SYN-ACK flood attacks
        if TCP in pkt:
            if tcp_flags == 'S':  # Check for SYN flood attack
                self.FILTERED_ACTIVITIES['TCP-SYN']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                attack_type = 'TCP-SYN PACKET'
            if tcp_flags == 'SA':  # Check for SYN-ACK flood attack
                self.FILTERED_ACTIVITIES['TCP-SYNACK']['activities'].append([pkt.time, src_ip, dst_ip, src_mac])
                attack_type = 'TCP-SYNACK PACKET'

        # Log detected attacks to CSV
        if attack_type:
            self.csv_writer.writerow([pkt.time, src_ip, dst_ip, attack_type, load_len])  # Log details of the detected attack
            self.csv_file.flush()  # Ensure data is written to the file

        # Update the recent activities with the timestamp of the current packet
        self.RECENT_ACTIVITIES.append([pkt.time, src_ip, dst_ip, src_mac, protocol])
        
    def start_sniffing(self):
        self.flag = True  # Set the flag to start sniffing
        sniff_thread = threading.Thread(target=self.sniffer_threader)  # Create a thread for sniffing
        analyze_thread = threading.Thread(target=self.analyze_threader)  # Create a thread for analyzing
        sniff_thread.start()  # Start the sniffing thread
        analyze_thread.start()  # Start the analyzing thread

    def stop_sniffing(self):
        self.flag = False  # Set the flag to stop sniffing
        self.csv_file.close()  # Close the CSV file
