import struct
import random
import socket
import time
import tkinter as tk


def generate_random_mac():
    """Generate a random MAC address."""
    return ':'.join(f"{random.randint(0, 255):02x}" for _ in range(6))


def generate_random_ip():
    """Generate a random IPv4 address."""
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))


def perform_ping(address, text_widget):
    """Perform a simplified ping using sockets and display the results."""
    try:
        # Resolve the hostname to an IP
        ip = socket.gethostbyname(address)
        text_widget.insert(tk.END, f"Pinging {address} [{ip}]...\n")
        text_widget.insert(tk.END, "-" * 50 + "\n")
        text_widget.update()

        # Simulate the system's IP and MAC
        system_ip = "192.168.0.101"  # A random local IP for display
        system_mac = generate_random_mac()  # Simulate system MAC address

        text_widget.insert(tk.END, f"System IP: {system_ip}\n")
        text_widget.insert(tk.END, f"System MAC: {system_mac}\n")

        # Simulate the destination and source MAC
        dest_mac = generate_random_mac()  # Random destination MAC
        src_mac = generate_random_mac()   # Random source MAC
        text_widget.insert(tk.END, f"Source MAC: {src_mac}, Destination MAC: {dest_mac}\n")
        text_widget.insert(tk.END, f"Protocol: IPv4 (0x0800)\n")

        # Start a simple ping simulation
        for i in range(4):  # Perform 4 "pings"
            start_time = time.time()
            try:
                # Connect to the address
                with socket.create_connection((ip, 80), timeout=2):
                    elapsed_time = (time.time() - start_time) * 1000  # Convert to ms
                    text_widget.insert(tk.END, f"Reply from {ip}: time={elapsed_time:.2f}ms\n")
            except socket.timeout:
                text_widget.insert(tk.END, f"Request timed out.\n")
            except Exception as e:
                text_widget.insert(tk.END, f"Error: {e}\n")

            time.sleep(1)  # Wait 1 second between pings

        text_widget.insert(tk.END, "-" * 50 + "\n")
        text_widget.yview(tk.END)

    except socket.gaierror:
        text_widget.insert(tk.END, f"Could not resolve address: {address}\n")
    except Exception as e:
        text_widget.insert(tk.END, f"An error occurred: {e}\n")
    text_widget.yview(tk.END)


def simulate_packet_processing(text_widget):
    """Simulate packet processing with random data for each run."""
    # Generate random source and destination MAC addresses
    src_mac = generate_random_mac()
    dest_mac = generate_random_mac()

    # Generate random IPv4 addresses
    src_ip = generate_random_ip()
    dest_ip = generate_random_ip()

    # Simulate an Ethernet frame and IPv4 packet
    fake_packet_data = struct.pack('! 6s 6s H', bytes(dest_mac.encode()), bytes(src_mac.encode()), 0x0800)  # Ethernet header
    fake_packet_data += struct.pack('! B B H H 4s 4s', 0x45, 0x00, 0x00, 0x28, socket.inet_aton(src_ip), socket.inet_aton(dest_ip))

    # Process the generated packet
    process_packet(fake_packet_data, text_widget)


def process_packet(packet_data, text_widget):
    """Process the packet, unpacking Ethernet and IP data."""
    # Unpack Ethernet frame
    dest_mac, src_mac, eth_proto = struct.unpack('! 6s 6s H', packet_data[:14])
    dest_mac = ':'.join(f"{byte:02x}" for byte in dest_mac)
    src_mac = ':'.join(f"{byte:02x}" for byte in src_mac)
    packet_info = f"Destination MAC: {dest_mac}, Source MAC: {src_mac}, Protocol: {hex(eth_proto)}\n"

    # Process IPv4 packets
    if eth_proto == 0x0800:  # IPv4
        packet_info += "IPv4 packet detected.\n"
        # Unpack IPv4 header (Skipping initial 14 bytes for Ethernet)
        ip_header = packet_data[14:]  # Start from the IP header
        version_header_length = ip_header[0]
        header_length = (version_header_length & 15) * 4  # IP header length (in bytes)

        # Add the valid IP header length to the output
        packet_info += f"Valid IP header length: {header_length} bytes\n"

        # Only unpack if the header is long enough
        if len(ip_header) >= header_length:
            ttl, proto, src, target = struct.unpack('! x B B 2x 4s 4s', ip_header[:header_length])  # Skip the first byte (version/IHL) when unpacking
            src_ip = '.'.join(str(i) for i in src)
            target_ip = '.'.join(str(i) for i in target)
            packet_info += f"Source IP: {src_ip}, Target IP: {target_ip}, TTL: {ttl}, Protocol: {proto}\n"
        else:
            packet_info += "Invalid IP header length.\n"  # Invalid header length message
    else:
        packet_info += "Non-IPv4 packet detected.\n"

    # Display the packet information in the Tkinter text widget
    text_widget.insert(tk.END, packet_info)
    text_widget.insert(tk.END, "-" * 50 + "\n")  # Add a separator for readability
    text_widget.yview(tk.END)  # Scroll to the bottom


def setup_gui():
    """Set up the Tkinter GUI for packet simulation and pinging."""
    root = tk.Tk()
    root.title("Network Utility - Packet Simulator & Ping Utility")

    # Create a Text widget to display the results
    text_widget = tk.Text(root, height=20, width=80)
    text_widget.pack(padx=10, pady=10)

    # Entry widget for the ping utility input (if needed)
    entry = tk.Entry(root, width=50)
    entry.pack(pady=10)

    # Button to perform both packet simulation or ping
    def on_button_click():
        address = entry.get()
        if address:  # If the user has entered a valid IP/hostname, do the ping
            perform_ping(address, text_widget)
        else:  # If no address is entered, simulate a packet
            simulate_packet_processing(text_widget)

    # Button to perform either task
    main_button = tk.Button(root, text="Execute", command=on_button_click)
    main_button.pack(pady=5)

    # Button to clear the text widget
    def clear_text():
        text_widget.delete(1.0, tk.END)

    clear_button = tk.Button(root, text="Clear", command=clear_text)
    clear_button.pack(pady=10)

    # Start the Tkinter event loop
    root.mainloop()


# Run the Tkinter GUI
setup_gui()