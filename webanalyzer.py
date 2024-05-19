import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, TCP, IP, Ether, Raw
import threading
import tkinter.messagebox as messagebox
import datetime

# Global variable to store packet list and count
packet_list = []
packet_count = 0
sniffer = None
sniffing = False
hover_popup = None  # Global variable to store hover popup
http_filter_enabled = False  # Flag to indicate whether HTTP filtering is enabled or not


def extract_http_website(packet):
    if Raw in packet:
        raw_data = packet[Raw].load.decode("utf-8", "ignore")
        lines = raw_data.split("\r\n")
        for line in lines:
            if line.startswith("Host:"):
                return line.split(" ")[1]
    return "Unknown"


def packet_callback(packet):
    global packet_count
    packet_count += 1

    # Filter packets based on HTTP and HTTPS protocols
    if TCP in packet and (packet.haslayer(IP) and packet.haslayer(Ether)):
        if packet[TCP].dport == 80 or packet[TCP].dport == 443:
            website_name = extract_http_website(packet)
            if http_filter_enabled:
                dst_ip = packet[IP].dst if IP in packet else "-"
                dst_port = packet[TCP].dport if TCP in packet else "-"
                messagebox.showwarning("Unsafe HTTP",
                                       f"Access to HTTP website {website_name} is disabled for security reasons.")
                return  # Return if HTTP filtering is enabled and HTTP traffic is detected
            # Append packet to the list
            packet_list.append(packet)

            # Display the packet in the Treeview
            display_packet(packet_count, packet)
        elif packet[TCP].dport == 5000:
            # Append packet to the list
            packet_list.append(packet)

            # Display the packet in the Treeview
            display_packet(packet_count, packet)

            # Bind the closing action of the unsafe website to the thank you message
            root.protocol("WM_DELETE_WINDOW", lambda: show_thank_you_message(website_name))


def show_thank_you_message(website_name):
    messagebox.showinfo("Thank You", f"Thank you for closing the unsafe website {website_name}. You are now safe.")


def display_packet(packet_num, packet):
    # Extract relevant information from the packet
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src_mac = packet[Ether].src if Ether in packet else "-"
    dst_mac = packet[Ether].dst if Ether in packet else "-"
    src_ip = packet[IP].src if IP in packet else "-"
    dst_ip = packet[IP].dst if IP in packet else "-"
    src_port = packet[TCP].sport if TCP in packet else "-"
    dst_port = packet[TCP].dport if TCP in packet else "-"
    protocol = "HTTP" if packet[TCP].dport == 80 else "HTTPS" if packet[TCP].dport == 443 else "-"
    packet_data = get_packet_data(packet)  # Function to get packet data
    raw_data = packet[Raw].load.decode("utf-8", "ignore") if Raw in packet else "-"  # Extract raw data and decode it

    # Insert packet information into the Treeview
    tree.insert("", "end", values=(
        packet_num, timestamp, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, protocol, packet_data, raw_data))


def get_packet_data(packet):
    # Check if the packet contains HTTP data based on destination port
    if TCP in packet and packet[TCP].dport == 80:
        return "HTTP"
    elif TCP in packet and packet[TCP].dport == 443:
        return "HTTPS"
    return "-"


def show_packet_info(event):
    # Get the item selected in the Treeview
    item = tree.selection()[0]
    packet_info = tree.item(item, "values")

    # Extract the raw data of the selected packet
    raw_data = packet_info[-1]

    # Display raw data in a message box
    if raw_data != "-":
        messagebox.showinfo("Raw Data", f"Raw Data:\n{raw_data}")


def apply_filter():
    # Clear existing items in the Treeview
    for item in tree.get_children():
        tree.delete(item)

    # Filter packets based on the selected protocol
    selected_protocol = filter_var.get()
    for packet_num, packet in enumerate(packet_list, start=1):
        if selected_protocol == "All" or selected_protocol == get_packet_data(packet):
            display_packet(packet_num, packet)


def start_sniffing():
    global sniffer, sniffing
    if not sniffing:
        sniffing = True
        # Start capturing packets using scapy sniff function
        # Adjust the 'iface' parameter to your network interface (e.g., 'eth0' for Ethernet)
        sniffer = threading.Thread(target=lambda: sniff(prn=packet_callback, store=False))
        sniffer.start()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)


def stop_sniffing():
    global sniffer, sniffing
    if sniffing:
        sniffing = False
        if sniffer and sniffer.is_alive():
            sniffer.join()
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)


def detect_vulnerabilities():
    # Check if both username and password are present in any packet's raw data
    for packet_num, packet in enumerate(packet_list, start=1):
        raw_data = packet[Raw].load.decode("utf-8", "ignore") if Raw in packet else ""
        if "uname" in raw_data.lower() and "pass" in raw_data.lower():
            messagebox.showinfo("Detection Result", "Username and password leaked")
            return  # Stop further processing once a match is found

    # If no match is found
    messagebox.showinfo("Detection Result", "No vulnerabilities detected")

    # Display detection results
    if detected_vulnerabilities:
        messagebox.showinfo("Detection Result", "\n".join(detected_vulnerabilities))
    else:
        messagebox.showinfo("Detection Result", "No vulnerabilities detected")


def detect_sql_injection():
    # Simulate the detection of SQL injection
    detected_vulnerabilities = []

    # Search for SQL injection patterns in packet raw data
    for packet in packet_list:
        raw_data = packet[Raw].load.decode("utf-8", "ignore") if Raw in packet else ""
        if "DROP TABLE" in raw_data or "DELETE FROM" in raw_data:
            detected_vulnerabilities.append(
                "SQL Injection detected in packet {}".format(packet_list.index(packet) + 1))

    # Display detection results
    if detected_vulnerabilities:
        messagebox.showinfo("SQL Injection Detection Result", "\n".join(detected_vulnerabilities))
    else:
        messagebox.showinfo("SQL Injection Detection Result", "No SQL injection vulnerabilities detected")


def on_hover(event):
    global hover_popup
    # Get the item under the cursor
    x, y = event.x_root, event.y_root
    item = tree.identify_row(event.y)

    # Get the raw data of the packet
    packet_info = tree.item(item, "values")
    if packet_info:
        raw_data = packet_info[-1]

        # Display raw data in a popup window
        if raw_data != "-":
            # Destroy any existing popup
            if hover_popup:
                hover_popup.destroy()

            # Calculate popup position
            popup_x = x + 10
            popup_y = y + 10

            # Calculate popup size
            popup_width = 600  # Adjust as needed
            popup_height = 300  # Adjust as needed

            hover_popup = tk.Toplevel(root)
            hover_popup.geometry("{}x{}+{}+{}".format(popup_width, popup_height, popup_x, popup_y))
            hover_popup.overrideredirect(True)
            hover_popup.bind("<Leave>", lambda e: hover_popup.destroy())

            raw_data_label = tk.Text(hover_popup, font=("Helvetica", 12), bg="black", fg="white")
            raw_data_label.insert(tk.END, raw_data)
            raw_data_label.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)


def toggle_http_filter():
    global http_filter_enabled
    http_filter_enabled = not http_filter_enabled
    if http_filter_enabled:
        http_filter_toggle_button.config(text="HTTP Filter: ON", style="HTTPFilterOn.TButton")
    else:
        http_filter_toggle_button.config(text="HTTP Filter: OFF", style="HTTPFilterOff.TButton")


# Create a Tkinter window
root = tk.Tk()
root.title("Packet Analyzer")

# Increase font size for all elements
root.option_add("*Font", "Helvetica 12")

# Create a Frame for filter options
filter_frame = ttk.Frame(root)
filter_frame.pack(pady=10)

# Filter label and entry
filter_label = ttk.Label(filter_frame, text="Filter:")
filter_label.grid(row=0, column=0, padx=5)

filter_var = tk.StringVar()
filter_combobox = ttk.Combobox(filter_frame, textvariable=filter_var, values=["All", "HTTP", "HTTPS"])
filter_combobox.grid(row=0, column=1, padx=5)
filter_combobox.current(0)

filter_button = ttk.Button(filter_frame, text="Apply Filter", command=apply_filter, style="Dark.TButton")
filter_button.grid(row=0, column=2, padx=5)

# Create a Frame for start and stop sniffing buttons
button_frame = ttk.Frame(root)
button_frame.pack(pady=10)

# Start button
start_button = ttk.Button(button_frame, text="Start Sniffing", command=start_sniffing, style="Start.TButton")
start_button.grid(row=0, column=0, padx=5)

# Stop button
stop_button = ttk.Button(button_frame, text="Stop Sniffing", command=stop_sniffing, state=tk.DISABLED,
                         style="Stop.TButton")
stop_button.grid(row=0, column=1, padx=5)

# Enable/Disable HTTP Filtering checkbox
http_filter_checkbox = ttk.Checkbutton(button_frame, text="Enable HTTP Filtering", command=toggle_http_filter)
http_filter_checkbox.grid(row=0, column=2, padx=5)

# Detect Vulnerabilities button
detect_vulnerabilities_button = ttk.Button(button_frame, text="Detect Vulnerabilities", command=detect_vulnerabilities)
detect_vulnerabilities_button.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

# Detect SQL Injection button
detect_sql_injection_button = ttk.Button(button_frame, text="Detect SQL Injection", command=detect_sql_injection)
detect_sql_injection_button.grid(row=1, column=2, columnspan=2, padx=5, pady=5)
detect_sql_injection_button.configure(style="SQL.TButton")

# Create a custom style for buttons and filter button
style = ttk.Style()
style.configure("Start.TButton", foreground="white", background="green")
style.map("Start.TButton", background=[("active", "darkgreen")])
style.configure("Stop.TButton", foreground="white", background="red")
style.map("Stop.TButton", background=[("active", "darkred")])
style.configure("Dark.TButton", foreground="white", background="black")
style.map("Dark.TButton", background=[("active", "darkgray")])

# Define style for SQL Injection button
style.configure("SQL.TButton", foreground="white", background="blue")
style.map("SQL.TButton", background=[("active", "darkblue")])

# Create a Treeview widget to display packet information in a tabular format
tree = ttk.Treeview(root, columns=(
    "Packet Number", "Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Source Port",
    "Destination Port", "Protocol", "Packet Data", "Raw Data"))
tree.heading("#0", text="", anchor=tk.CENTER)
tree.heading("Packet Number", text="Packet Number", anchor=tk.CENTER)
tree.heading("Timestamp", text="Timestamp", anchor=tk.CENTER)
tree.heading("Source MAC", text="Source MAC", anchor=tk.CENTER)
tree.heading("Destination MAC", text="Destination MAC", anchor=tk.CENTER)
tree.heading("Source IP", text="Source IP", anchor=tk.CENTER)
tree.heading("Destination IP", text="Destination IP", anchor=tk.CENTER)
tree.heading("Source Port", text="Source Port", anchor=tk.CENTER)
tree.heading("Destination Port", text="Destination Port", anchor=tk.CENTER)
tree.heading("Protocol", text="Protocol", anchor=tk.CENTER)
tree.heading("Packet Data", text="Packet Data", anchor=tk.CENTER)
tree.heading("Raw Data", text="Raw Data", anchor=tk.CENTER)
tree.pack(fill=tk.BOTH, expand=True)

# Bind events
tree.bind("<Double-1>", show_packet_info)
tree.bind("<Motion>", on_hover)  # Hover event

# Start the Tkinter event loop
root.mainloop()