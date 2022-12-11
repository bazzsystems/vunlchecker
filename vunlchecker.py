import socket
import time
import tkinter as tk
from tkinter import ttk
from threading import Thread

def on_click():
  ip = ip_entry.get()
  scan_thread = Thread(target=start_scan, args=(ip, 'scan_results.txt'))
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

def start_scan(ip, output_file):
  open_ports = []

  # Scan the first 65535 ports
  for port in range(1, 65536):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.01)

    # Check if the port is open
    if s.connect_ex((ip, port)) == 0:
      open_ports.append(port)
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

  # Save the results to a file
  with open(output_file, 'w') as f:
    f.write('Open ports:\n')
    for port in open_ports:
      f.write(str(port) + '\n')
    f.write('\nVulnerabilities:\n')
    for vulnerability in vulnerabilities:
      f.write(vulnerability + '\n')
    f.write('\nFirewall: ' + firewall + '\n')


# Create GUI window
root = tk.Tk()
root.title("IP Scanner")
root.geometry("500x500")
root.configure(bg="lightgrey")
font = ("sans-serif", 12)
fg_color = "blue"

# Create input field for IP address
ip_label = tk.Label(root, text="IP Address:", font=font, bg="white", fg=fg_color)
ip_label.place(x=10, y=10)
ip_entry = tk.Entry(root, width=20, font=font)
ip_entry.place(x=120, y=10)

# Create button to start scan
scan_button = tk.Button(root, text="Scan", font=font, bg="white", fg=fg_color, command=on_click)
scan_button.place(x=10, y=50)

# Create progress bar
progress_bar = ttk.Progressbar(root, orient="horizontal", length=200, mode="determinate")
progress_bar.place(x=120, y=50)

# Create output field
output_text = tk.Text(root, width=50, height=20, font=font)
output_text.place(x=10, y=100)

# Create input field for domain
domain_label = tk.Label(root, text="Domain:", font=font, bg="white", fg=fg_color)
domain_label.place(x=10, y=350)
domain_entry = tk.Entry(root, width=20, font=font)
domain_entry.place(x=120, y=350)

# Create button to get IP address from domain
domain_button = tk.Button(root, text="Get IP", font=font, bg="white", fg=fg_color, command=on_click_domain)
domain_button.place(x=10, y=390)

# Create output field for domain
domain_output_text = tk.Text(root, width=50, height=1, font=font)
domain_output_text.place(x=10, y=430)

root.mainloop()
