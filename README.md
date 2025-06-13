# PORTSSS-Multithreaded-Port-Scanner
Recon_tool

# PortSSS - Python Multi-threaded TCP/UDP Port Scanner

`PortSSS` is a fast and efficient port scanner written in Python. It scans TCP and UDP ports, performs banner grabbing, and uses multithreading with progress tracking. Results are saved to a CSV file.

---

##  Features

- Multithreaded TCP and UDP port scanning
- Banner grabbing for known services
- Service identification
- ICMP handling for UDP (via `scapy`)
- Progress bar using `tqdm`
- Results saved to a CSV file
- Thread-safe printing

---

##  Requirements

- Python 3.6+
- Modules:
  - `pyfiglet`
  - `tqdm`
  - `scapy`

Install with:

```bash
pip install -r requirements.txt

