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
from tkinterdnd2 import DND_FILES, TkinterDnD
import math

# Configuration
NOTIFICATION_PORT = 50001
DATA_PORT = 50002
PING_TIMEOUT = 0.5
SCAN_THREADS = 100
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
        self.total_ips = (1 << host_bits) - 2
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
                timeout_value = str(int(PING_TIMEOUT * 1000))
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
                pass
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
        for _ in range(SCAN_THREADS):
            threading.Thread(target=self.ping_worker, daemon=True).start()
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

class ModernGUI(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberSend v2.0")
        self.geometry("1000x800")
        self.configure(bg='#2c3e50')
        self.style = ttk.Style()
        self._configure_styles()
        self.scanner = NetworkScanner()
        self.server = FileTransferServer(self)
        self.scanning = False
        self.current_progress = 0
        self.total_progress = 1
        self.loader_angle = 0
        self.show_splash_screen()
        self._create_widgets()
        self.server.start_server()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.drop_target_register(DND_FILES)
        self.dnd_bind('<<Drop>>', self.on_drop)

    def show_splash_screen(self):
        splash = tk.Toplevel(self)
        splash.overrideredirect(True)
        splash_width = 300
        splash_height = 300
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - splash_width) // 2
        y = (screen_height - splash_height) // 2
        splash.geometry(f"{splash_width}x{splash_height}+{x}+{y}")
        splash.configure(bg='#3498db')
        canvas = tk.Canvas(splash, width=300, height=300, highlightthickness=0)
        canvas.pack()
        for i in range(300):
            r = int(52 + (41 - 52) * i / 300)
            g = int(152 + (128 - 152) * i / 300)
            b = int(219 + (185 - 219) * i / 300)
            color = f'#{r:02x}{g:02x}{b:02x}'
            canvas.create_line(0, i, 300, i, fill=color)
        canvas.create_text(150, 150, text="CyberSend v2.0", font=("Arial", 24, "bold"), fill="white", anchor="center")
        canvas.create_text(150, 200, text="Fast and secure file transfers", font=("Arial", 12), fill="white", anchor="center")
        self.withdraw()
        splash.update()
        self.after(2000, lambda: [splash.destroy(), self.deiconify(), self.state('zoomed')])

    def _configure_styles(self):
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#2c3e50')
        self.style.configure('TLabel', background='#2c3e50', foreground='#ecf0f1', font=('Arial', 12))
        self.style.configure('TButton', background='#3498db', foreground='white', font=('Arial', 10), borderwidth=0)
        self.style.configure('Treeview', background='#34495e', fieldbackground='#34495e', foreground='#ecf0f1', rowheight=25)
        self.style.configure('Treeview.Heading', font=('Arial', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#2980b9')])
        self.style.configure('Red.Horizontal.TProgressbar', background='#e74c3c', troughcolor='#2c3e50')
        self.style.configure('Green.Horizontal.TProgressbar', background='#2ecc71', troughcolor='#2c3e50')

    def _create_widgets(self):
        main_frame = ttk.Frame(self)
        main_frame.pack(expand=True, fill='both', padx=30, pady=30)
        self.interface_combo = ttk.Combobox(main_frame, state='readonly')
        self.interface_combo.pack(fill='x', pady=10)
        self._load_interfaces()
        scan_frame = ttk.Frame(main_frame)
        scan_frame.pack(fill='x', pady=10)
        self.scan_btn = ttk.Button(scan_frame, text="Scan Network", command=self.start_scan)
        self.scan_btn.pack(side='left', padx=5)
        self.stop_btn = ttk.Button(scan_frame, text="Stop Scan", command=self.stop_scan, state='disabled')
        self.stop_btn.pack(side='left', padx=5)
        self.loader_canvas = tk.Canvas(main_frame, width=50, height=50, bg='#2c3e50', highlightthickness=0)
        self.loader_canvas.pack(pady=5)
        self.scan_progress = ttk.Progressbar(main_frame, style='Green.Horizontal.TProgressbar', mode='determinate')
        self.scan_progress.pack(fill='x', pady=5)
        self.progress_label = ttk.Label(main_frame, text="Ready to scan")
        self.progress_label.pack(pady=5)
        self.device_tree = ttk.Treeview(main_frame, columns=('ip', 'status'), show='headings')
        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.heading('status', text='Status')
        self.device_tree.column('ip', width=150)
        self.device_tree.column('status', width=100)
        self.device_tree.pack(expand=True, fill='both', pady=10)
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill='x', pady=10)
        self.transfer_btn = ttk.Button(control_frame, text="Send File", command=self.select_file)
        self.transfer_btn.pack(side='right', padx=5)
        self.transfer_progress = ttk.Progressbar(main_frame, style='Red.Horizontal.TProgressbar', mode='determinate')
        self.transfer_progress.pack(fill='x', pady=5)
        self.transfer_label = ttk.Label(main_frame, text="No active transfers")
        self.transfer_label.pack(pady=5)

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
        self._start_loader_animation()
        threading.Thread(target=self._perform_scan, args=(selected_iface,), daemon=True).start()
        self.after(UPDATE_INTERVAL, self._update_ui_progress)

    def stop_scan(self):
        self.scanning = False
        self.scanner.scanning = False
        self.scan_btn['state'] = 'normal'
        self.stop_btn['state'] = 'disabled'
        self._stop_loader_animation()

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
        self._stop_loader_animation()
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
                text=f"Scanning... {self.current_progress}/{self.total_progress} ({progress:.1f}%)"
            )
            self._update_loader_animation()
            self.after(UPDATE_INTERVAL, self._update_ui_progress)
        else:
            self.scan_progress['value'] = 0
            self._stop_loader_animation()

    def _start_loader_animation(self):
        self.loader_canvas.delete("all")
        self.loader_angle = 0
        self._update_loader_animation()

    def _update_loader_animation(self):
        self.loader_canvas.delete("loader")
        center_x, center_y = 25, 25
        radius = 20
        start_angle = self.loader_angle
        end_angle = start_angle + 90
        self.loader_canvas.create_arc(center_x - radius, center_y - radius, center_x + radius, center_y + radius,
                                      start=start_angle, extent=90, style=tk.ARC, outline="#ecf0f1", width=4, tags="loader")
        self.loader_angle = (self.loader_angle + 10) % 360

    def _stop_loader_animation(self):
        self.loader_canvas.delete("loader")

    def select_file(self):
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a device first")
            return
        target_ip = self.device_tree.item(selected[0])['values'][0]
        file_path = filedialog.askopenfilename()
        if file_path:
            threading.Thread(target=self.initiate_transfer, args=(target_ip, file_path), daemon=True).start()

    def on_drop(self, event):
        selected = self.device_tree.selection()
        if not selected:
            messagebox.showerror("Error", "Select a device first")
            return
        target_ip = self.device_tree.item(selected[0])['values'][0]
        file_path = event.data.strip('{}')  # Clean up dropped file path
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
