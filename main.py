import sys
import os
import socket
import struct
import subprocess
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from queue import Queue
import netifaces
from PIL import Image, ImageTk
import ftplib
from io import BytesIO
from datetime import datetime
import math

# Configuration
NOTIFICATION_PORT = 50001
DATA_PORT = 50002
PING_TIMEOUT = 1
SCAN_THREADS = 100  # Increased from 50 to 100
UPDATE_INTERVAL = 100  # ms

class NetworkScanner:
    def __init__(self, progress_callback=None):
        self.active_devices = []
        self.ping_queue = Queue()
        self.scanning = False
        self.progress_callback = progress_callback
        self.total_ips = 0
        self.processed_ips = 0
        self.lock = threading.Lock()

    def get_interfaces(self):
        interfaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr_info in addrs[netifaces.AF_INET]:
                    if 'addr' in addr_info and 'netmask' in addr_info:
                        interfaces.append({
                            'name': iface,
                            'ip': addr_info['addr'],
                            'netmask': addr_info['netmask']
                        })
        return interfaces

    def calculate_network(self, ip, netmask):
        ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
        mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
        network_int = ip_int & mask_int
        return socket.inet_ntoa(struct.pack('!I', network_int))

    def generate_ips(self, network, netmask):
        network_int = struct.unpack('!I', socket.inet_aton(network))[0]
        mask_int = struct.unpack('!I', socket.inet_aton(netmask))[0]
        host_bits = 32 - bin(mask_int).count('1')
        self.total_ips = (1 << host_bits) - 2  # Subtract network and broadcast
        for host in range(1, self.total_ips + 1):
            current_ip_int = network_int | host
            yield socket.inet_ntoa(struct.pack('!I', current_ip_int))

    def ping_worker(self):
        while True:
            ip = self.ping_queue.get()
            if ip is None:
                break
            
            if sys.platform.startswith('win'):
                count_param = '-n'
                timeout_param = '-w'
                timeout_value = str(int(PING_TIMEOUT * 1000))  # Convert seconds to milliseconds
            else:
                count_param = '-c'
                timeout_param = '-W'
                timeout_value = str(PING_TIMEOUT)
            
            command = ['ping', count_param, '1', timeout_param, timeout_value, ip]
            try:
                subprocess.check_output(command, stderr=subprocess.STDOUT)
                with self.lock:
                    if ip not in self.active_devices:
                        self.active_devices.append(ip)
            except subprocess.CalledProcessError:
                pass  # Host unreachable or ping failed
            
            with self.lock:
                self.processed_ips += 1
                if self.progress_callback:
                    self.progress_callback(self.processed_ips, self.total_ips)
            
            self.ping_queue.task_done()

    def scan_network(self, ip, netmask):
        self.active_devices = []
        self.processed_ips = 0
        self.total_ips = 0
        self.scanning = True
        network = self.calculate_network(ip, netmask)
        
        # Start worker threads
        for _ in range(SCAN_THREADS):
            threading.Thread(target=self.ping_worker, daemon=True).start()
            
        # Generate IPs and add to queue
        ip_generator = self.generate_ips(network, netmask)
        for ip in ip_generator:
            self.ping_queue.put(ip)
            
        self.ping_queue.join()
        self.scanning = False
        return self.active_devices

class FileTransferServer:
    def __init__(self, gui_update):
        self.gui_update = gui_update
        self.server_socket = None
        self.running = False

    def start_server(self):
        self.running = True
        threading.Thread(target=self._notification_listener, daemon=True).start()

    def _notification_listener(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('0.0.0.0', NOTIFICATION_PORT))
        self.server_socket.listen(5)
        
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_request, args=(client, addr), daemon=True).start()
            except OSError:
                break

    def _handle_request(self, client, addr):
        try:
            data = client.recv(1024).decode()
            if data.startswith('TRANSFER_REQUEST'):
                parts = data.split('|')
                if len(parts) == 2:
                    file_info = parts[1]
                    filename, filesize = file_info.split(':')
                    response = self.gui_update.show_transfer_prompt(addr[0], filename, filesize)
                    client.send(response.encode())
                    if response == 'ACCEPT':
                        self._initiate_transfer(addr[0], filename, filesize)
                else:
                    client.send("DECLINE".encode())
        finally:
            client.close()

    def _initiate_transfer(self, sender_ip, filename, filesize):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('0.0.0.0', DATA_PORT))
            s.listen(1)
            conn, _ = s.accept()
            with conn:
                with open(filename, 'wb') as f:
                    total_received = 0
                    while total_received < int(filesize):
                        data = conn.recv(4096)
                        total_received += len(data)
                        f.write(data)

class ModernGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberSend v2.0")
        self.geometry("1000x800")
        self.configure(bg='#1a1a1a')
        self.style = ttk.Style()
        self._configure_styles()
        
        self.scanner = NetworkScanner()
        self.server = FileTransferServer(self)
        self.scanning = False
        self.current_progress = 0
        self.total_progress = 1  # Prevent division by zero
        
        self.show_splash_screen()
        self._create_widgets()
        self.server.start_server()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def show_splash_screen(self):
        splash = tk.Toplevel()
        splash.overrideredirect(True)
        splash.geometry("300x200")
        splash.configure(bg='#1a1a1a')
        label = ttk.Label(splash, text="CyberSend v2.0", font=("Arial", 24), background='#1a1a1a', foreground='white')
        label.pack(expand=True)
        splash.update()
        time.sleep(2)  # Display for 2 seconds
        splash.destroy()

    def _configure_styles(self):
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#1a1a1a')
        self.style.configure('TLabel', background='#1a1a1a', foreground='white')
        self.style.configure('TButton', background='#333', foreground='white')
        self.style.configure('Treeview', background='#333', fieldbackground='#333', foreground='white')
        self.style.map('TButton', background=[('active', '#444')])
        self.style.configure('Red.Horizontal.TProgressbar', background='#e74c3c')
        self.style.configure('Green.Horizontal.TProgressbar', background='#2ecc71')

    def _create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Interface Selection
        self.interface_combo = ttk.Combobox(main_frame, state='readonly')
        self.interface_combo.pack(fill='x', pady=10)
        self._load_interfaces()
        
        # Scan Controls
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill='x', pady=10)
        
        self.scan_btn = ttk.Button(scan_frame, text="Scan Network", command=self.start_scan)
        self.scan_btn.pack(side='left')
        
        self.stop_btn = ttk.Button(scan_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=10)
        
        # Progress Display
        self.scan_progress = ttk.Progressbar(main_frame, style='Green.Horizontal.TProgressbar', mode='determinate')
        self.scan_progress.pack(fill='x', pady=5)
        
        self.progress_label = ttk.Label(main_frame, text="Ready to scan")
        self.progress_label.pack()
        
        # Device List
        self.device_tree = ttk.Treeview(main_frame, columns=('ip', 'status'), show='headings')
        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.heading('status', text='Status')
        self.device_tree.pack(expand=True, fill='both', pady=10)
        
        # Transfer Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=10)
        
        self.transfer_btn = ttk.Button(control_frame, text="Send File", command=self.select_file)
        self.transfer_btn.pack(side='right')
        
        # Transfer Progress
        self.transfer_progress = ttk.Progressbar(main_frame, style='Red.Horizontal.TProgressbar', mode='determinate')
        self.transfer_progress.pack(fill='x', pady=5)
        self.transfer_label = ttk.Label(main_frame, text="No active transfers")
        self.transfer_label.pack()

    def _load_interfaces(self):
        interfaces = self.scanner.get_interfaces()
        self.interface_combo['values'] = [f"{iface['name']} ({iface['ip']})" for iface in interfaces]
        if interfaces:
            self.interface_combo.current(0)

    def start_scan(self):
        if not self.interface_combo.get():
            messagebox.showerror("Error", "Select a network interface first")
            return
        
        self.scanning = True
        self.scan_btn['state'] = 'disabled'
        self.stop_btn['state'] = 'normal'
        self.device_tree.delete(*self.device_tree.get_children())
        
        selected_iface = self.scanner.get_interfaces()[self.interface_combo.current()]
        self.scanner = NetworkScanner(self.update_scan_progress)
        
        threading.Thread(target=self._perform_scan, args=(selected_iface,), daemon=True).start()
        self.after(UPDATE_INTERVAL, self._update_ui_progress)

    def stop_scan(self):
        self.scanning = False
        self.scanner.scanning = False
        self.scan_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'

    def _perform_scan(self, iface):
        try:
            active_ips = self.scanner.scan_network(iface['ip'], iface['netmask'])
            self.after(0, self._scan_completed, active_ips)
        except Exception as e:
            self.after(0, messagebox.showerror, "Scan Error", str(e))

    def _scan_completed(self, active_ips):
        self.scanning = False
        self.scan_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'
        
        for ip in active_ips:
            self.device_tree.insert('', 'end', values=(ip, 'Online'))
        
        self.progress_label.config(text=f"Scan completed: {len(active_ips)} devices found")

    def update_scan_progress(self, processed, total):
        self.current_progress = processed
        self.total_progress = total

    def _update_ui_progress(self):
        if self.scanning:
            progress = self.current_progress / self.total_progress * 100
            self.scan_progress['value'] = progress
            self.progress_label.config(
                text=f"Scanning... {self.current_progress}/{self.total_progress} "
                     f"({progress:.1f}%)"
            )
            self.after(UPDATE_INTERVAL, self._update_ui_progress)
        else:
            self.scan_progress['value'] = 0

    def select_file(self):
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a device first")
            return
        
        target_ip = self.device_tree.item(selected[0])['values'][0]
        file_path = filedialog.askopenfilename()  # Select a single file
        if file_path:
            threading.Thread(target=self.initiate_transfer, args=(target_ip, file_path), daemon=True).start()

    def initiate_transfer(self, target_ip, file_path):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(10)
                s.connect((target_ip, NOTIFICATION_PORT))
                filename = os.path.basename(file_path)
                filesize = os.path.getsize(file_path)
                s.send(f"TRANSFER_REQUEST|{filename}:{filesize}".encode())
                response = s.recv(1024).decode()
                if response == 'ACCEPT':
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_socket:
                        data_socket.settimeout(30)
                        data_socket.connect((target_ip, DATA_PORT))
                        self._send_file(data_socket, file_path)
                    self.after(0, messagebox.showinfo, "Success", "Transfer completed")
                else:
                    self.after(0, messagebox.showinfo, "Declined", "Recipient declined transfer")
        except Exception as e:
            self.after(0, messagebox.showerror, "Error", f"Transfer failed: {str(e)}")

    def _send_file(self, data_socket, file_path):
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                data_socket.send(chunk)

    def show_transfer_prompt(self, sender_ip, filename, filesize):
        result = messagebox.askquestion(
            "Incoming Transfer",
            f"{sender_ip} wants to send {filename} ({filesize} bytes)\nAccept transfer?",
            icon='question'
        )
        return "ACCEPT" if result == "yes" else "DECLINE"

    def on_close(self):
        self.server.running = False
        if self.server.server_socket:
            self.server.server_socket.close()
        self.destroy()

if __name__ == "__main__":
    app = ModernGUI()
    app.mainloop()
