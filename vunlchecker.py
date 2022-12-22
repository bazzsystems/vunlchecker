import socket
import time
import tkinter as tk
from tkinter import ttk
from threading import Thread
import requests
import json

def on_click():
  ip = ip_entry.get()
  ports_range = ports_entry.get()
  if ports_range:
      ports = range(int(ports_range.split("-")[0]), int(ports_range.split("-")[1])+1)
  else:
      ports = range(1, 65536)
  scan_thread = Thread(target=start_scan, args=(ip, ports, 'scan_results.txt'))
  scan_thread.start()
  while scan_thread.is_alive():
    progress_bar.step()
    with open('scan_results.txt', 'r') as f:
      output = f.read()
      output_text.delete(1.0, tk.END)
      output_text.insert(tk.END, output)
    root.update()

def on_click_domain():
  domain = domain_entry.get()
  try:
    ip = socket.gethostbyname(domain)
    domain_output_text.delete(1.0, tk.END)
    domain_output_text.insert(tk.END, ip)
  except:
    domain_output_text.delete(1.0, tk.END)
    domain_output_text.insert(tk.END, 'Invalid domain')

def start_scan(ip, ports, output_file):
  open_ports = []
  services = {}

  # Scan the specified ports
  for port in ports:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.01)

    # Check if the port is open
    if s.connect_ex((ip, port)) == 0:
      open_ports.append(port)
      try:
          services[port] = socket.getservbyport(port)
      except OSError:
          services[port] = "Unknown service"
    s.close()

  # Check for vulnerabilities
  vulnerabilities = []
  for port in open_ports:
    # Check for known vulnerabilities on specific ports
    if port == 22:
      vulnerabilities.append('SSH')
    elif port == 80:
      vulnerabilities.append('HTTP')
    elif port == 443:
      vulnerabilities.append('HTTPS')
    elif port == 3389:
      vulnerabilities.append('RDP')
    elif port == 445:
      vulnerabilities.append('SMB')

  # Check for a firewall
  if len(open_ports) == 0:
    firewall = 'Yes'
  else:
    firewall = 'No'

  # Use AI to give a vulnerability assessment
  ai_assessment = get_ai_assessment(ip, open_ports, services)

  # Save the results to a file
  with open(output_file, 'w') as f:
    f.write('Open ports:\n')
    for port in open_ports:
      f.write(str(port) + ': ' + services[port] + '\n')
    f.write('\nVulnerabilities:\n')
    for vulnerability in vulnerabilities:
      f.write(vulnerability + '\n')
    f.write('\nFirewall: ' + firewall + '\n')
    f.write('\nAI assessment:\n')
    f.write(ai_assessment + '\n')

def get_ai_assessment(ip, open_ports, services):
  # Replace this with a call to your AI model
  return "AI assessment not available"

# Create GUI window
root = tk.Tk()
root.title("IP Scanner")
root.geometry("500x500")
root.configure(bg="lightgrey")
font = ("sans-serif", 12)
fg_color = "blue"

# Create input field for IP address
ip_label = tk.Label(root, text="IP address:", font=font, bg="lightgrey", fg=fg_color)
ip_label.place(x=10, y=10)
ip_entry = tk.Entry(root, width=20, font=font)
ip_entry.place(x=120, y=10)

# Create input field for ports
ports_label = tk.Label(root, text="Ports (optional, e.g. 1-1000):", font=font, bg="white", fg=fg_color)
ports_label.place(x=10, y=40)
ports_entry = tk.Entry(root, width=20, font=font)
ports_entry.place(x=250, y=40)

# Create button to start scan
scan_button = tk.Button(root, text="Scan", font=font, bg="white", fg=fg_color, command=on_click)
scan_button.place(x=10, y=80)

# Create progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")
progress_bar.place(x=120, y=80)

# Create output field
output_text = tk.Text(root, width=50, height=20, font=font)
output_text.place(x=10, y=120)

# Create input field for domain
domain_label = tk.Label(root, text="Domain:", font=font, bg="white", fg=fg_color)
domain_label.place(x=10, y=350)
domain_entry = tk.Entry(root, width=20, font=font)
domain_entry.place(x=120, y=350)

# Create button to resolve domain
resolve_button = tk.Button(root, text="Resolve", font=font, bg="white", fg=fg_color, command=on_click_domain)
resolve_button.place(x=10, y=390)

# Create output field for domain resolution
domain_output_text = tk.Text(root, width=20, height=1, font=font)
domain_output_text.place(x=120, y=390)

# Start the GUI loop
root.mainloop()


