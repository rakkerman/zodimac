import subprocess
import nmapthon as nmap  # Use the python-nmap package
import re
import platform
import random
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox


# Zodiac signs for sun and moon
ZODIAC_SIGNS = [
    "Aries", "Taurus", "Gemini", "Cancer", "Leo", "Virgo",
    "Libra", "Scorpio", "Sagittarius", "Capricorn", "Aquarius", "Pisces"
]

# Predefined lists of horoscope components
RELATIONSHIP_WITH_WORLD = [
    "This device is a beacon of innovation, lighting the way for others.",
    "In the grand scheme of things, this device plays a crucial role in connecting the world.",
    "This device is a silent guardian, always watching and protecting.",
    "The world sees this device as a symbol of progress and modernity.",
    "This device is a bridge between the past and the future.",
    "The world benefits greatly from the presence of this device."
]

GENERIC_LINES = [
    "Today is a day to embrace change and welcome new opportunities.",
    "Patience is key; good things come to those who wait.",
    "The stars align in favor of progress today.",
    "Trust in the journey; it will lead to great discoveries.",
    "A little kindness goes a long way in building connections.",
    "The universe has a plan, and this device is part of it."
]

ADDITIONAL_LINES = [
    "Creativity shines brightly in the work of this device.",
    "A new connection will bring unexpected joy to its operations.",
    "Reflection on goals and aspirations will lead to greater achievements.",
    "An opportunity for growth is on the horizon for this device.",
    "Hard work will soon pay off in unexpected and rewarding ways.",
    "Staying open to new ideas and perspectives will yield great results."
]

SELF_PERCEPTION = [
    "This device sees itself as a vital part of the network, always ready to serve.",
    "It views itself as a guardian of data, ensuring everything flows smoothly.",
    "This device believes it is a catalyst for innovation and progress.",
    "It sees itself as a bridge, connecting people and ideas seamlessly.",
    "This device perceives itself as a silent but essential contributor to daily life.",
    "It views itself as a symbol of reliability and trustworthiness."
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
    relationship_with_world = random.choice(RELATIONSHIP_WITH_WORLD)
    generic_line = random.choice(GENERIC_LINES)
    additional_line = random.choice(ADDITIONAL_LINES)
    self_perception = random.choice(SELF_PERCEPTION)

    # Combine into a multi-line horoscope
    horoscope = (
        f"{relationship_with_world}\n"
        f"{generic_line}\n"
        f"{additional_line}\n"
        f"{self_perception}"
    )

    return horoscope

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
            # Assign zodiac signs and horoscope immediately
            sun_sign, moon_sign = get_zodiac_signs(mac)
            horoscope = get_unique_horoscope(mac)
            devices.append({
                'ip': ip,
                'mac': mac,
                'device': 'Device is not identifiable',
                'zodiac': f"Sun: {sun_sign}, Moon: {moon_sign}",
                'horoscope': horoscope
            })

    return devices

def run_nmap_scan(ip, options, progress_callback, sudo_password=None):
    # Use subprocess with sudo for elevated privileges
    command = ["sudo", "nmap", *options, ip]
    progress_callback(f"Performing scan on {ip} with options: {options}...")

    try:
        if sudo_password:
            # Run with sudo and provide the password
            result = subprocess.run(
                command,
                input=f"{sudo_password}\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60  # Timeout after 60 seconds
            )
        else:
            # Run without sudo (not recommended for -O or -A)
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60  # Timeout after 60 seconds
            )

        if result.returncode != 0:
            progress_callback(f"Error scanning {ip}: {result.stderr}")
            return None

        return result.stdout
    except subprocess.TimeoutExpired:
        progress_callback(f"Scan on {ip} timed out after 60 seconds.")
        return None
    except Exception as e:
        progress_callback(f"Error scanning {ip}: {str(e)}")
        return None

def extract_device_info(nmap_output):
    # Extract device information (OS details and MAC address) from Nmap output
    device = None  # Use None to indicate no OS details were found
    mac_address = None  # Use None to indicate no MAC address was found

    # Extract OS details
    os_match = re.search(r"OS details:\s+(.+)", nmap_output)
    if os_match:
        device = os_match.group(1).strip()

    # Extract MAC address
    mac_match = re.search(r"MAC Address:\s+([0-9A-Fa-f:]+)", nmap_output)
    if mac_match:
        mac_address = mac_match.group(1).strip()

    return device, mac_address

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Zodimac")
        self.root.geometry("1000x800")  # Increased window size

        # Password input frame
        self.password_frame = ttk.LabelFrame(self.root, text="Enter Sudo Password")
        self.password_frame.pack(fill=tk.X, padx=10, pady=10)

        self.password_entry = ttk.Entry(self.password_frame, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5, pady=5)

        self.submit_button = ttk.Button(self.password_frame, text="Submit", command=self.elevate_privileges)
        self.submit_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # ARP Results display
        self.arp_frame = ttk.LabelFrame(self.root, text="ARP Scan Results")
        self.arp_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.arp_text = scrolledtext.ScrolledText(self.arp_frame, wrap=tk.WORD, state='disabled', height=10)
        self.arp_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Progress report display
        self.progress_frame = ttk.LabelFrame(self.root, text="Progress Report")
        self.progress_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.progress_text = scrolledtext.ScrolledText(self.progress_frame, wrap=tk.WORD, state='disabled', height=5)
        self.progress_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Start button (initially disabled)
        self.start_button = ttk.Button(self.arp_frame, text="Start Scan", command=self.start_scan, state='disabled')
        self.start_button.pack(pady=10)

        # Nmap Results display
        self.results_frame = ttk.LabelFrame(self.root, text="Nmap Scan Results")
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, state='disabled')
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Store sudo password
        self.sudo_password = None
        # Track pop-up window positions
        self.popup_x_offset = 0
        self.popup_y_offset = 0

    def elevate_privileges(self):
        # Get the sudo password from the entry field
        self.sudo_password = self.password_entry.get()
        if self.sudo_password:
            result = subprocess.run(["sudo", "-S", "echo", "Privileges elevated"], input=f"{self.sudo_password}\n", text=True, stderr=subprocess.PIPE)
            if result.returncode != 0:
                messagebox.showerror("Error", "Incorrect sudo password. Please try again.")
            else:
                self.log_progress("Privileges elevated successfully.")
                # Enable the start button after successful privilege elevation
                self.start_button.config(state='normal')
                # Disable the password input frame
                self.password_entry.config(state='disabled')
                self.submit_button.config(state='disabled')
                # Force the GUI to update
                self.root.update()
        else:
            messagebox.showerror("Error", "No sudo password provided. Please try again.")

    def log_progress(self, message):
        # Log progress to the progress report text box
        self.progress_text.config(state='normal')
        self.progress_text.insert(tk.END, message + "\n")
        self.progress_text.config(state='disabled')
        self.progress_text.yview(tk.END)
        self.root.update()  # Force GUI update

    def display_arp_results(self, devices):
        # Display ARP scan results immediately
        self.arp_text.config(state='normal')
        self.arp_text.delete("1.0", tk.END)
        self.arp_text.insert(tk.END, "ARP Scan Results:\n")
        for device in devices:
            self.arp_text.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
        self.arp_text.insert(tk.END, "-" * 60 + "\n")
        self.arp_text.config(state='disabled')
        self.arp_text.yview(tk.END)
        self.root.update()  # Force GUI update

    def display_nmap_result(self, device, nmap_output):
        # Display Nmap scan result for a single device in the GUI
        self.results_text.config(state='normal')
        self.results_text.insert(tk.END, f"IP Address: {device['ip']}\n")
        self.results_text.insert(tk.END, f"MAC Address: {device['mac']}\n")
        self.results_text.insert(tk.END, f"Device: {device['device']}\n")
        self.results_text.insert(tk.END, f"Zodiac: {device['zodiac']}\n")
        self.results_text.insert(tk.END, f"Horoscope:\n{device['horoscope']}\n")
        self.results_text.insert(tk.END, f"Raw Nmap Output:\n{nmap_output}\n")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        self.results_text.config(state='disabled')
        self.results_text.yview(tk.END)
        self.root.update()  # Force GUI update

        # Show a popup window with the Nmap result
        popup = tk.Toplevel(self.root)
        popup.title(f"Scan Result for {device['ip']}")
        popup.geometry("500x200")

        # Position the popup window
        popup.geometry(f"+{self.popup_x_offset}+{self.popup_y_offset}")
        self.popup_x_offset += 520  # Offset for the next popup
        if self.popup_x_offset > 1000:  # Reset offset if it goes off-screen
            self.popup_x_offset = 0
            self.popup_y_offset += 420

        result_text = scrolledtext.ScrolledText(popup, wrap=tk.WORD)
        result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        result_text.insert(tk.END, f"IP Address: {device['ip']}\n")
        result_text.insert(tk.END, f"MAC Address: {device['mac']}\n")
        result_text.insert(tk.END, f"Device: {device['device']}\n")
        result_text.insert(tk.END, f"Zodiac: {device['zodiac']}\n")
        result_text.insert(tk.END, f"Horoscope:\n{device['horoscope']}\n")
        result_text.insert(tk.END, f"Raw Nmap Output:\n{nmap_output}\n")
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

        # Assign "Router" to the first found IP
        if devices:
            devices[0]['device'] = "Router"
            # Show a popup for the router
            self.display_nmap_result(devices[0], "Router detected. No Nmap scan performed.")

        # Step 2: Perform intense scan on each active device and update device info
        self.log_progress("\nPerforming intense scans on active devices...")
        for device in devices[1:]:  # Skip the router
            ip = device['ip']
            self.log_progress(f"Starting scan for {ip}...")
            scan_output = run_nmap_scan(ip, ["-O"], self.log_progress, self.sudo_password)
            if scan_output:
                # Extract device information from Nmap output
                device_info, mac_address = extract_device_info(scan_output)
                if device_info:
                    device['device'] = device_info
                if mac_address:
                    device['mac'] = mac_address

            # If no OS details found, retry with -A
            if device['device'] == "Device is not identifiable":
                self.log_progress(f"No OS details found for {ip}. Retrying with -A...")
                scan_output = run_nmap_scan(ip, ["-A"], self.log_progress, self.sudo_password)
                if scan_output:
                    # Extract device information from Nmap output
                    device_info, mac_address = extract_device_info(scan_output)
                    if device_info:
                        device['device'] = device_info
                    if mac_address:
                        device['mac'] = mac_address

            # If still no OS details found, retry with -A again
            if device['device'] == "Device is not identifiable":
                self.log_progress(f"No OS details found for {ip}. Final retry with -A and -Pn ")
                scan_output = run_nmap_scan(ip, ["-A","-Pn"], self.log_progress, self.sudo_password)
                if scan_output:
                    # Extract device information from Nmap output
                    device_info, mac_address = extract_device_info(scan_output)
                    if device_info:
                        device['device'] = device_info
                    if mac_address:
                        device['mac'] = mac_address

            # If still no OS details and no MAC address found, set default device name
            if device['device'] == "Device is not identifiable" and device['mac'] == "Unknown":
                device['device'] = "iPhone, unable to see device name"

            # Special case: If OS details are "FreeBSD 8.0-RC1-p1", set device name to "Playstation 5"
            if device['device'] == "FreeBSD 8.0-RC1-p1":
                device['device'] = "Playstation 5"

            # Display the Nmap result for this device
            self.display_nmap_result(device, scan_output)

        # Re-enable the start button after the scan is complete
        self.start_button.config(state='normal')
        self.root.update()  # Force GUI update

if __name__ == "__main__":
    # Create the GUI
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()