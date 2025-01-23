import socket
from concurrent.futures import ThreadPoolExecutor
from tkinter import *
from tkinter import ttk, messagebox, simpledialog
from threading import Thread
import time
import json
import logging
from datetime import datetime
from scapy.all import sniff, IP, TCP

# Configurare logging
logging.basicConfig(filename="port_scanner.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Descrieri ale porturilor standard
port_descriptions = {
    21: "FTP - Transfer de fișiere",
    22: "SSH - Administrare servere",
    23: "Telnet - Protocol de acces remote",
    25: "SMTP - Trimiterea emailurilor",
    53: "DNS - Rezolvarea numelor de domenii",
    80: "HTTP - Trafic web nesecurizat",
    110: "POP3 - Protocol pentru descărcarea emailurilor",
    143: "IMAP - Protocol pentru accesarea emailurilor",
    443: "HTTPS - Trafic web securizat",
    3389: "RDP - Remote Desktop Protocol",
}

def scan_port(ip, port, protocol):
    """Verifică dacă un port este deschis pentru protocolul specificat."""
    try:
        if protocol == "TCP":
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    return port
        elif protocol == "UDP":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(1)
                try:
                    s.sendto(b"\x00", (ip, port))
                    s.recvfrom(1024)
                    return port
                except socket.timeout:
                    pass
    except Exception as e:
        logging.error(f"Eroare la scanarea portului {port}: {e}")
        return None
    return None

def detect_service(port):
    """Detectează serviciul asociat unui port standard."""
    return port_descriptions.get(port, "Utilizare necunoscută")

def export_to_html(results, filename="scan_results.html"):
    """Exportă rezultatele scanării într-un fișier HTML."""
    try:
        with open(filename, "w") as f:
            f.write("<html><head><title>Rezultate Scanare Porturi</title></head><body>")
            f.write("<h1>Rezultate Scanare Porturi</h1>")
            f.write("<table border='1'><tr><th>Port</th><th>Serviciu</th><th>Protocol</th><th>Utilizare</th></tr>")
            for port, service, protocol, usage in results:
                f.write(f"<tr><td>{port}</td><td>{service}</td><td>{protocol}</td><td>{usage}</td></tr>")
            f.write("</table></body></html>")
        messagebox.showinfo("Succes", f"Rezultatele au fost salvate în {filename}.")
        logging.info(f"Rezultatele scanării exportate în {filename}.")
    except Exception as e:
        logging.error(f"Eroare la exportul rezultatelor: {e}")
        messagebox.showerror("Eroare", f"Nu s-a putut exporta: {e}")

def analyze_traffic(ip, ports):
    """Analizează traficul rețelei pe porturile date."""
    def packet_callback(packet):
        if IP in packet and TCP in packet:
            if packet[IP].src == ip and packet[TCP].sport in ports:
                logging.info(f"Pachet capturat de la {ip}, port {packet[TCP].sport}")
                print(packet.summary())

    logging.info("Începem analiza traficului...")
    sniff(filter=f"host {ip}", prn=packet_callback, timeout=10)
    logging.info("Analiza traficului finalizată.")

def check_vulnerabilities(port):
    """Verifică vulnerabilități cunoscute pentru un port."""
    vulnerabilities = {
        21: "FTP anonimizat activat",
        22: "Versiuni vechi de SSH",
        80: "Server HTTP fără HTTPS",
        443: "SSL/TLS nesigur",
    }
    return vulnerabilities.get(port, "Nicio vulnerabilitate cunoscută")

def scan_ports(ip, protocol, start_port, end_port, progress_bar, output_text, start_button, time_label):
    """Scanează porturile folosind fire de execuție."""
    output_text.delete(1.0, END)
    progress_bar['value'] = 0
    open_ports = []
    total_ports = end_port - start_port + 1
    start_button['state'] = 'disabled'

    start_time = time.time()

    def update_progress(port):
        progress_bar['value'] += 100 / total_ports
        progress_bar.update()
        output_text.insert(END, f"Scanez portul: {port}\n")

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(scan_port, ip, port, protocol): port for port in range(start_port, end_port + 1)}
        for future in futures:
            port = futures[future]
            try:
                result = future.result()
                if result:
                    service = detect_service(result)
                    usage = port_descriptions.get(result, "Utilizare necunoscută")
                    vulnerability = check_vulnerabilities(result)
                    open_ports.append((result, service, protocol, usage))
                    logging.info(f"Port deschis: {result} ({service}), Vuln: {vulnerability}, Utilizare: {usage}")
                    output_text.insert(END, f"Port {result} ({service}), Vuln: {vulnerability}, Utilizare: {usage}\n")
            except Exception as e:
                logging.error(f"Eroare la scanarea portului {port}: {e}")
            update_progress(port)

    elapsed_time = time.time() - start_time

    if open_ports:
        output_text.insert(END, f"Porturi deschise pe {ip} ({protocol}):\n")
        for port, service, protocol, usage in open_ports:
            output_text.insert(END, f"{port} ({service}): {usage}\n")
    else:
        output_text.insert(END, f"Nicio port deschis pe {ip} pentru protocolul {protocol}.\n")

    export_to_html(open_ports)

    time_label.config(text=f"Timp total: {elapsed_time:.2f} secunde")
    start_button['state'] = 'normal'

def start_scan(ip_entry, protocol_var, start_port_entry, end_port_entry, progress_bar, output_text, start_button, time_label):
    """Inițiază scanarea pe un fir separat."""
    ip = ip_entry.get().strip()
    protocol = protocol_var.get()
    try:
        start_port = int(start_port_entry.get())
        end_port = int(end_port_entry.get())
        if start_port < 1 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        messagebox.showwarning("Eroare", "Interval de porturi invalid. Introduceți valori între 1 și 65535.")
        return

    if not ip:
        messagebox.showwarning("Eroare", "Introduceți o adresă IP validă.")
        return

    thread = Thread(target=scan_ports, args=(ip, protocol, start_port, end_port, progress_bar, output_text, start_button, time_label))
    thread.start()

# Interfața grafică
root = Tk()
root.title("Scanare Porturi Avansată")
root.geometry("700x800")
root.configure(bg="#1e1e2f")

Label(root, text="Scanare Porturi", font=("Arial", 18, "bold"), bg="#1e1e2f", fg="#f8f8f2").pack(pady=10)

frame = Frame(root, bg="#1e1e2f")
frame.pack(pady=10)

Label(frame, text="Adresă IP:", font=("Arial", 12), bg="#1e1e2f", fg="#f8f8f2").grid(row=0, column=0, padx=5, pady=5)
ip_entry = Entry(frame, width=20, font=("Arial", 12))
ip_entry.grid(row=0, column=1, padx=5, pady=5)

Label(frame, text="Protocol:", font=("Arial", 12), bg="#1e1e2f", fg="#f8f8f2").grid(row=1, column=0, padx=5, pady=5)
protocol_var = StringVar(value="TCP")
protocol_menu = ttk.Combobox(frame, textvariable=protocol_var, values=["TCP", "UDP"], state="readonly", font=("Arial", 12))
protocol_menu.grid(row=1, column=1, padx=5, pady=5)

Label(frame, text="Port de început:", font=("Arial", 12), bg="#1e1e2f", fg="#f8f8f2").grid(row=2, column=0, padx=5, pady=5)
start_port_entry = Entry(frame, width=10, font=("Arial", 12))
start_port_entry.grid(row=2, column=1, padx=5, pady=5)

Label(frame, text="Port de sfârșit:", font=("Arial", 12), bg="#1e1e2f", fg="#f8f8f2").grid(row=3, column=0, padx=5, pady=5)
end_port_entry = Entry(frame, width=10, font=("Arial", 12))
end_port_entry.grid(row=3, column=1, padx=5, pady=5)

start_button = Button(frame, text="Scanează", command=lambda: start_scan(ip_entry, protocol_var, start_port_entry, end_port_entry, progress_bar, output_text, start_button, time_label), bg="#50fa7b", fg="#1e1e2f", font=("Arial", 12))
start_button.grid(row=1, column=2, padx=5, pady=5)

progress_bar = ttk.Progressbar(root, length=400, mode='determinate')
progress_bar.pack(pady=10)

time_label = Label(root, text="Timp total: 0 secunde", font=("Arial", 12), bg="#1e1e2f", fg="#f8f8f2")
time_label.pack(pady=5)

output_text = Text(root, wrap='word', height=15, width=70, bg="#282a36", fg="#f8f8f2", font=("Arial", 12))
output_text.pack(pady=10)

root.mainloop()
