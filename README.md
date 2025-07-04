# Nmap_Tool

A Python assistant for interactive, advanced, and stealthy Nmap scanning and passive reconnaissance, with a polite "Alfred" persona.

---

## What the Script Does

- **Interactive Nmap Scanning:**  
  Guides you through various types of Nmap scans (basic, advanced, stealth, output formats, etc.) with user-friendly prompts.
- **Passive Reconnaissance:**  
  Lets you run tools like `whois`, `nslookup`, `dig`, `theHarvester`, and crt.sh lookups for information gathering without active scanning.
- **Profiles:**  
  Save and load your favorite scan configurations for quick reuse.
- **Stealth & Evasion:**  
  Supports decoys, timing, MAC spoofing, and other evasion techniques.
- **Batch & File Input:**  
  Scan multiple targets from a file.
- **Legal Reminder:**  
  Reminds you to scan only with permission.

---

## How to Run It

1. **Install Python 3.7+**  
   Make sure Python 3 is installed.

2. **Install Requirements**  
   If you want to use passive recon features like crt.sh, install `requests`:
   ```
   pip install -r requirements.txt
   ```

3. **Run the Script**
   ```
   python3 Nmap_Tool.py
   ```
   or on Windows:
   ```
   python Nmap_Tool.py
   ```

4. **Follow the Prompts**  
   The script will guide you through all options interactively.

---

## Requirements

- **Python 3.7+**
- **Nmap** installed and in your PATH
- (Optional) `requests` Python library for crt.sh lookups
- (Optional) External tools for passive recon: `whois`, `nslookup`, `dig`, `theHarvester`

---

## Example Usage

```bash
python3 Nmap_Tool.py
```
- Choose "Basic Scan" for a quick scan of an IP or range.
- Choose "Scan Type" for SYN, UDP, OS detection, etc.
- Choose "Advanced" for timing, evasion, and custom arguments.
- Choose "Passive Reconnaissance" for OSINT without touching the target.
- Choose "Stealth Reconnaissance" for slow, decoyed scans.
- Save/load scan profiles for repeatable operations.

---

## Features in Detail

- **Banner & Legal Warning:**  
  Shows a stylized ASCII banner and reminds you about legal scanning.

- **Main Menu:**  
  ```
  1. Basic Scan
  2. Scan Type
  3. Advanced
  4. Output Format & Script
  5. Passive Reconnaissance
  6. Stealth Reconnaissance
  7. Profiles
  8. Help/Info
  0. Exit
  ```

- **Basic Scan:**  
  Scan a single IP, range, subnet, hostname, or list from a file. Optionally specify port ranges.

- **Scan Type:**  
  Choose from SYN, UDP, OS detection, version, aggressive, vuln scripts, or custom NSE scripts.

- **Advanced:**  
  Configure timing, verbosity, DNS resolution, scan delay, retries, MAC spoofing, fragmentation, randomization, and custom Nmap arguments.

- **Output Format & Script:**  
  Save results in normal, XML, grepable, or all formats. Optionally run NSE scripts.

- **Passive Reconnaissance:**  
  Run OSINT tools (`whois`, `nslookup`, `dig`, `theHarvester`, crt.sh) without touching the target directly.

- **Stealth Reconnaissance:**  
  Use decoys, slow timing, scan delay, and other evasion options for stealthy scans.

- **Profiles:**  
  Save and load scan configurations for repeatable scans.

- **Help/Info:**  
  Shows a help menu with explanations.

---

## requirements.txt

```
requests
```
*(Only needed for crt.sh lookups. If you don't use that feature, you can skip this.)*

---

## .gitignore (optional)

```
*.pyc
__pycache__/
profile_*.txt
*.log
```

---

## Example Profile File

When you save a profile, it creates a file like `profile_myprofile.txt` containing the Nmap command.

---

## Notes

- **Run as administrator/root** if you want to use SYN scans or other privileged Nmap features.
- **Always scan with permission.**
- **You can extend the script** to add more tools or automate reporting.