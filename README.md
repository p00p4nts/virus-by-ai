# MalwareTestBench

**⚠️ DISCLAIMER ⚠️**  
This repository contains proof-of-concept code for simulating malware behavior in controlled, ethical, and legal testing environments. It is intended **solely for educational and security research purposes** by authorized professionals, such as penetration testers, red teamers, and cybersecurity researchers. **DO NOT** use this code on systems or networks without explicit permission, as doing so may violate laws, including but not limited to the Computer Fraud and Abuse Act (CFAA) and other regional regulations. The author(s) assume **no liability** for misuse, damages, or legal consequences resulting from the use of this code. Use responsibly and at your own risk.

## Overview
MalwareTestBench is a toolkit for simulating worm propagation, network exploitation, and payload deployment in sandboxed environments. Features include:
- Network scanning and host enumeration
- Simulated infection via SMB and other vectors
- Encryption-based payload testing
- Persistence mechanisms for research purposes

## Usage
This code is intended for use in isolated virtual machines or lab environments. Example use cases include:
- Studying worm propagation algorithms
- Testing network security defenses
- Developing countermeasures against ransomware

## Installation
1. Install dependencies: `pip install pyinstaller pycryptodome cryptography`
2. Compile to executable: `pyinstaller --onefile --noconsole malware_test_bench.py`
3. Run in a sandboxed environment only.

## Warning
Misuse of this code can cause significant harm. Ensure compliance with all applicable laws and ethical guidelines.
