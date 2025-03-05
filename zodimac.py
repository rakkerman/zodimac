import subprocess
import re
import platform
import random
import socket
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, font

# Zodiac signs for sun and moon
ZODIAC_SIGNS = [
    "Aries", "Taurus", "Gemini", "Cancer", "Leo", "Virgo",
    "Libra", "Scorpio", "Sagittarius", "Capricorn", "Aquarius", "Pisces"
]

# Predefined lists of horoscope components
RELATIONSHIP_WORLD = [
    "This device is a beacon of innovation, lighting the way for others.",
    "In the grand scheme of things, this device plays a crucial role in connecting the world.",
    "This device is a silent guardian, always watching and protecting.",
    "The world sees this device as a symbol of progress and modernity.",
    "This device is a bridge between the past and the future.",
    "The world benefits greatly from the presence of this device.",
    # Controversial additions
    "This device is a double-edged sword, capable of both creation and destruction.",
    "The world fears this device, for it holds the power to disrupt the status quo.",
    "This device is a necessary evil, balancing chaos and order in the network.",
    "The world is wary of this device, as it thrives in the shadows of anonymity."
]

GENERIC_LINES = [
    "Today is a day to embrace change and welcome new opportunities.",
    "Patience is key; good things come to those who wait.",
    "The stars align in favor of progress today.",
    "Trust in the journey; it will lead to great discoveries.",
    "A little kindness goes a long way in building connections.",
    "The universe has a plan, and this device is part of it.",
    # Controversial additions
    "Today, the device may find itself at odds with its own purpose.",
    "The stars warn of potential conflicts with other devices in the network.",
    "Trust no one, for even the most reliable connections can betray you.",
    "The universe is indifferent; it is up to this device to carve its own path."
]

ADDITIONAL_LINES = [
    "Creativity shines brightly in the work of this device.",
    "A new connection will bring unexpected joy to its operations.",
    "Reflection on goals and aspirations will lead to greater achievements.",
    "An opportunity for growth is on the horizon for this device.",
    "Hard work will soon pay off in unexpected and rewarding ways.",
    "Staying open to new ideas and perspectives will yield great results.",
    # Controversial additions
    "This device may face a moral dilemma today; choose wisely.",
    "A hidden flaw in its design could lead to unexpected consequences.",
    "The device's actions today may have far-reaching, unintended effects.",
    "Beware of overconfidence; even the most secure systems have vulnerabilities."
]

SELF_PERCEPTION = [
    "This device sees itself as a vital part of the network, always ready to serve.",
    "It views itself as a guardian of data, ensuring everything flows smoothly.",
    "This device believes it is a catalyst for innovation and progress.",
    "It sees itself as a bridge, connecting people and ideas seamlessly.",
    "This device perceives itself as a silent but essential contributor to daily life.",
    "It views itself as a symbol of reliability and trustworthiness.",
    # Controversial additions
    "This device secretly questions its own purpose in the grand scheme of things.",
    "It sees itself as a rogue element, challenging the norms of the network.",
    "This device believes it is destined for greatness, even if it must break the rules.",
    "It views itself as a lone wolf, operating outside the boundaries of conventional systems."
]

def get_zodiac_signs(mac_address):
    # Extract the first 2 pairs for the sun sign and the next 2 pairs for the moon sign
    first_two_pairs = mac_address[:5].replace(":", "")  # First 4 characters for sun sign
    next_two_pairs = mac_address[6:11].replace(":", "")  # Next 4 characters for moon sign

    # Convert to integers and map to zodiac signs
    sun_index = int(first_two_pairs, 16) % len(ZODIAC_SIGNS)
    moon_index = int(next_two_pairs, 16) % len(ZODIAC_SIGNS)

    return ZODIAC_SIGNS[sun_index], ZODIAC_SIGNS[moon_index]

def get_unique_horoscope(mac_address):
    # Use the MAC address to seed the random number generator
    random.seed(int(mac_address.replace(":", ""), 16))

    # Randomly select unique components for the horoscope
    relationship_world = random.choice(RELATIONSHIP_WORLD)
    generic_line = random.choice(GENERIC_LINES)
    additional_line = random.choice(ADDITIONAL_LINES)
    self_perception = random.choice(SELF_PERCEPTION)

    # Combine into a multi-line horoscope
    horoscope = (
        f"{relationship_world}\n"
        f"{generic_line}\n"
        f"{additional_line}\n"
        f"{self_perception}"
    )

    return horoscope

def get_hostname(ip):
    try:
        # Resolve the hostname from the IP address
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except (socket.herror, socket.gaierror):
        return "Unknown"

def get_active_devices():
    # Run the 'arp -a' command to get the ARP table
    if platform.system() == "Windows":
        arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True).stdout
    else:
        arp_output = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, text=True).stdout

    # Parse the ARP table to extract IP and MAC addresses
    devices = []
    arp_pattern = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)")  # Works for Linux/macOS
    if platform.system() == "Windows":
        arp_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)")  # Works for Windows

    for match in arp_pattern.findall(arp_output):
        ip, mac = match
        # Skip broadcast addresses (e.g., *.*.*.255)
        if ip.endswith(".255"):
            continue
        # Filter out non-local IPs (e.g., multicast, broadcast)
        if ip.startswith(("192.168.", "10.", "172.16.")):  # Common private IP ranges
            # Get the hostname
            hostname = get_hostname(ip)
            # Assign zodiac signs and horoscope immediately
            sun_sign, moon_sign = get_zodiac_signs(mac)
            horoscope = get_unique_horoscope(mac)
            devices.append({
                'ip': ip,
                'mac': mac,
                'device': hostname,  # Use the resolved hostname
                'zodiac': f"Sun: {sun_sign}, Moon: {moon_sign}",
                'horoscope': horoscope
            })

    return devices

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zodimac")
        self.root.geometry("600x800")  # Increased window size

        # ARP Results display
        self.arp_frame = ttk.LabelFrame(self.root, text="Holistic Device Presence")
        self.arp_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.arp_text = scrolledtext.ScrolledText(self.arp_frame, wrap=tk.WORD, state='disabled', height=10)
        self.arp_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Progress bar
        self.progress_bar = ttk.Progressbar(self.arp_frame, orient="horizontal", length=800, mode="determinate")
        self.progress_bar.pack(pady=10)

        # Start button
        self.start_button = ttk.Button(self.arp_frame, text="Start Scan", command=self.start_scan)
        self.start_button.pack(pady=10)

        # Results display
        self.results_frame = ttk.LabelFrame(self.root, text="Horoscopic Overview")
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, state='disabled')
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Track pop-up window positions
        self.popup_x_offset = 0
        self.popup_y_offset = 0

    def log_progress(self, message):
        # Log progress to the progress report text box
        self.arp_text.config(state='normal')
        self.arp_text.insert(tk.END, message + "\n")
        self.arp_text.config(state='disabled')
        self.arp_text.yview(tk.END)
        self.root.update()  # Force GUI update

    def display_arp_results(self, devices):
        # Display ARP scan results immediately
        self.arp_text.config(state='normal')
        self.arp_text.delete("1.0", tk.END)
        self.arp_text.insert(tk.END, "Holistic devices in your little bubble network:\n")
        for device in devices:
            self.arp_text.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
        self.arp_text.insert(tk.END, "-" * 60 + "\n")
        self.arp_text.config(state='disabled')
        self.arp_text.yview(tk.END)
        self.root.update()  # Force GUI update

    def display_result(self, device):
        # Display scan result for a single device in the GUI
        self.results_text.config(state='normal')

        # Format IP and MAC address on the same line, with MAC starting at the 25th place
        ip_mac_line = f"IP: {device['ip']}".ljust(25) + f"MAC: {device['mac']}"
        self.results_text.insert(tk.END, ip_mac_line + "\n")

        # Format device name in bold and centered
        bold_font = font.Font(weight="bold", size=12)
        self.results_text.tag_configure("bold", font=bold_font)
        self.results_text.insert(tk.END, f"{device['device'].center(len(ip_mac_line))}\n", "bold")

        # Add a line of hyphens
        self.results_text.insert(tk.END, "-" * len(ip_mac_line) + "\n")

        # Format Zodiac centered
        self.results_text.insert(tk.END, "Zodiac".center(len(ip_mac_line)) + "\n")

        # Format Sun and Moon, with Moon starting at the 25th place
        sun_moon_line = f"{device['zodiac'].split(', ')[0]}".ljust(25) + f"{device['zodiac'].split(', ')[1]}"
        self.results_text.insert(tk.END, sun_moon_line + "\n")

        # Add a line of hyphens
        self.results_text.insert(tk.END, "-" * len(ip_mac_line) + "\n")

        # Format Horoscope centered
        self.results_text.insert(tk.END, "Horoscope".center(len(ip_mac_line)) + "\n")

        # Add the horoscope text
        self.results_text.insert(tk.END, device['horoscope'] + "\n")

        # Add a separator line
        self.results_text.insert(tk.END, "=" * len(ip_mac_line) + "\n\n")

        self.results_text.config(state='disabled')
        self.results_text.yview(tk.END)
        self.root.update()  # Force GUI update

        # Show a popup window with the result
        self.show_popup(device, ip_mac_line)

    def show_popup(self, device, ip_mac_line):
        # Create a popup window
        popup = tk.Toplevel(self.root)
        popup.title(f"Scan Result for {device['ip']}")
        popup.geometry("400x300")

        # Position the popup window
        popup.geometry(f"+{self.popup_x_offset}+{self.popup_y_offset}")
        self.popup_x_offset += 520  # Offset for the next popup
        if self.popup_x_offset > 1000:  # Reset offset if it goes off-screen
            self.popup_x_offset = 0
            self.popup_y_offset += 420

        # Create a scrolled text widget for the popup
        result_text = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Insert the formatted result into the popup
        result_text.insert(tk.END, ip_mac_line + "\n")
        result_text.insert(tk.END, f"{device['device'].center(len(ip_mac_line))}\n")
        result_text.insert(tk.END, "-" * len(ip_mac_line) + "\n")
        result_text.insert(tk.END, "Zodiac".center(len(ip_mac_line)) + "\n")
        result_text.insert(tk.END, f"{device['zodiac'].split(', ')[0]}".ljust(25) + f"{device['zodiac'].split(', ')[1]}\n")
        result_text.insert(tk.END, "-" * len(ip_mac_line) + "\n")
        result_text.insert(tk.END, "Horoscope".center(len(ip_mac_line)) + "\n")
        result_text.insert(tk.END, device['horoscope'] + "\n")
        result_text.insert(tk.END, "=" * len(ip_mac_line) + "\n")

        # Disable editing in the popup text widget
        result_text.config(state='disabled')

    def start_scan(self):
        # Disable the start button during the scan
        self.start_button.config(state='disabled')
        self.root.update()  # Force GUI update

        # Clear previous results
        self.arp_text.config(state='normal')
        self.arp_text.delete("1.0", tk.END)
        self.arp_text.config(state='disabled')

        self.results_text.config(state='normal')
        self.results_text.delete("1.0", tk.END)
        self.results_text.config(state='disabled')
        self.root.update()  # Force GUI update

        # Step 1: Get active devices using ARP and assign zodiac signs and horoscopes
        self.log_progress("Fetching active devices using ARP and assigning zodiac signs and horoscopes...")
        devices = get_active_devices()

        if not devices:
            self.log_progress("No active devices found.")
            self.start_button.config(state='normal')
            self.root.update()  # Force GUI update
            return

        # Display ARP results immediately
        self.display_arp_results(devices)

        # Step 2: Assign "Router" to the first found IP and skip hostname resolution for it
        if devices:
            devices[0]['device'] = "Router"
            self.display_result(devices[0])
            self.progress_bar["value"] = 100 / len(devices)  # Update progress bar
            self.root.update()
            time.sleep(5)  # Add a 5-second delay after displaying the router

        # Step 3: Display results for each remaining device with a 5-second delay
        self.log_progress("\nDisplaying results for active devices...")
        for i, device in enumerate(devices[1:], start=1):  # Skip the router
            # Resolve hostname for non-router devices
            if device['device'] == "Unknown":
                device['device'] = get_hostname(device['ip'])
            self.display_result(device)
            self.progress_bar["value"] = (i + 1) * 100 / len(devices)  # Update progress bar
            self.root.update()
            time.sleep(5)  # Add a 5-second delay between devices

        # Re-enable the start button after the scan is complete
        self.start_button.config(state='normal')
        self.root.update()  # Force GUI update

if __name__ == "__main__":
    # Create the GUI
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()