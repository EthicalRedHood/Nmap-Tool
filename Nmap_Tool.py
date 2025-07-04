import sys
import subprocess
import datetime
import socket
import glob

def print_banner():
    banner = r"""
____  _____ ____  _   _  ___   ___  ____  
|  _ \| ____|  _ \| | | |/ _ \ / _ \|  _ \ 
| |_) |  _| | | | | |_| | | | | | | | | |
|  _ <| |___| |_| |  _  | |_| | |_| | |_| |
|_| \_\_____|____/|_| |_|\___/ \___/|____/ 
                                           
 _   _    _    ____ _  _______ ____  
| | | |  / \  / ___| |/ / ____|  _ \ 
| |_| | / _ \| |   | ' /|  _| | |_) |
|  _  |/ ___ \ |___| . \| |___|  _ < 
|_| | /_/   \_\____|_|\_\_____|_| \_\
    """
    print(banner)

def get_choice(prompt, options):
    print("\n" + f"Sir, {prompt}")
    for k, v in options.items():
        print(f"{k}. {v}")
    while True:
        choice = input("Your selection, if I may inquire: ").strip()
        if choice in options:
            return choice
        print("Pardon me, Sir, but that is not a valid choice. Might I trouble you to try again?")

def print_legal_warning():
    print("\nSir, may I remind you: Please ensure you have proper authorization before scanning any network or host. Unauthorised scanning may be illegal.\n")

def print_help():
    print("""
Alfred's Nmap Assistant - Help Menu

- Basic Scan: Quick scan of a single IP, range, subnet, or hostname.
- Scan Type: Choose from SYN, UDP, OS detection, version, scripts, etc.
- Advanced: Combine multiple options, timing, evasion, and more.
- Output Format & Script: Save results in various formats, run scripts.
- Stealth Reconnaissance: Slow, stealthy scan with decoys.
- Passive Reconnaissance: Gather info without sending packets to the target.
- Profiles: Save and load your favorite scan configurations.
- Legal: Only scan with permission, Sir.

For further assistance, simply ask.
""")

def save_profile(profile_name, cmd):
    with open(f"profile_{profile_name}.txt", "w") as f:
        f.write(" ".join(cmd))
    print(f"Profile '{profile_name}' saved, Sir.")

def load_profile(profile_name):
    try:
        with open(f"profile_{profile_name}.txt", "r") as f:
            cmd = f.read().strip().split()
        print(f"Profile '{profile_name}' loaded, Sir.")
        return cmd
    except FileNotFoundError:
        print(f"Profile '{profile_name}' not found, Sir.")
        return None

def passive_recon():
    target = input("Sir, kindly provide the target domain or IP for passive reconnaissance: ").strip()
    print("Which passive recon tools would you like to use, Sir?")
    tools = {
        '1': 'whois',
        '2': 'nslookup',
        '3': 'dig',
        '4': 'theHarvester',
        '5': 'crt.sh (certificate search)',
        '6': 'Shodan (requires API key)',
        '0': 'Done'
    }
    selected = []
    while True:
        for k, v in tools.items():
            print(f"{k}. {v}")
        choice = input("Select a tool to add (or 0 to finish): ").strip()
        if choice == '0':
            break
        if choice in tools and tools[choice] not in selected:
            selected.append(tools[choice])
    print("\nProceeding with:", ", ".join(selected))
    for tool in selected:
        if tool == 'whois':
            print("\nPerforming whois lookup, Sir...")
            subprocess.run(["whois", target])
        elif tool == 'nslookup':
            print("\nPerforming DNS lookup, Sir...")
            subprocess.run(["nslookup", target])
        elif tool == 'dig':
            print("\nPerforming dig, Sir...")
            subprocess.run(["dig", target])
        elif tool == 'theHarvester':
            print("\nRunning theHarvester, Sir...")
            subprocess.run(["theHarvester", "-d", target, "-b", "all"])
        elif tool == 'crt.sh (certificate search)':
            print("\nSearching crt.sh for certificates, Sir...")
            import requests
            url = f"https://crt.sh/?q={target}&output=json"
            try:
                resp = requests.get(url, timeout=10)
                if resp.ok:
                    print(resp.text)
                else:
                    print("crt.sh lookup failed, Sir.")
            except Exception as e:
                print(f"My apologies, Sir. crt.sh lookup failed: {e}")
        elif tool == 'Shodan (requires API key)':
            print("\nShodan integration not implemented, Sir. (API key required)")
    save = input("Would you like to save these results to a file, Sir? (y/n): ").strip().lower()
    if save == 'y':
        print("Saving not implemented in this snippet, Sir, but can be added.")

def main():
    print_banner()
    print_legal_warning()
    while True:
        main_options = {
            '1': "Basic Scans",
            '2': "Scan Type",
            '3': "Advanced",
            '4': "Output Format & Script",
            '5': "Passive Reconnaissance",
            '6': "Stealth Reconnaissance",
            '7': "Profiles",
            '8': "Help/Info",
            '0': "Exit"
        }
        choice = get_choice("how may I assist you today?", main_options)

        if choice == '0':
            print("Very good, Sir. Exiting the program as per your request.")
            sys.exit()

        elif choice == '1':
            # Basic Scan (with batch support)
            target_types = {
                '1': 'Single IP',
                '2': 'IP Range',
                '3': 'Subnet',
                '4': 'Hostname',
                '5': 'From file',
                '6': 'Find my public IP address'
            }
            t_choice = get_choice("please specify the type of target you wish to scan:", target_types)
            if t_choice == '6':
                print("One moment, Sir. I shall determine your IP addresses...")
                # Get public IP
                try:
                    import urllib.request
                    public_ip = urllib.request.urlopen('https://api.ipify.org').read().decode('utf8')
                    print(f"Sir, your public IP address appears to be: {public_ip}")
                except Exception as e:
                    print(f"My apologies, Sir. I could not determine your public IP address: {e}")
                    public_ip = None

                # Get private IP
                try:
                    hostname = socket.gethostname()
                    private_ip = socket.gethostbyname(hostname)
                    print(f"Sir, your private IP address appears to be: {private_ip}")
                except Exception as e:
                    print(f"My apologies, Sir. I could not determine your private IP address: {e}")
                    private_ip = None

                # Ask which to scan
                options = {}
                if public_ip:
                    options['1'] = f"Scan public IP ({public_ip})"
                if private_ip:
                    options['2'] = f"Scan private IP ({private_ip})"
                options['0'] = "Return to menu"

                scan_choice = get_choice("Which address would you like to scan, Sir?", options)
                if scan_choice == '1' and public_ip:
                    targets = [public_ip]
                elif scan_choice == '2' and private_ip:
                    targets = [private_ip]
                else:
                    print("Very good, Sir. Returning to the menu.")
                    return
            elif t_choice == '5':
                file_path = input("Sir, kindly provide the path to the file with targets (one per line): ").strip()
                with open(file_path) as f:
                    targets = [line.strip() for line in f if line.strip()]
            else:
                t_value = input(f"Sir, kindly provide the {target_types[t_choice]}: ").strip()
                if t_choice == '1' or t_choice == '4':
                    targets = [t_value]
                elif t_choice == '2':
                    targets = [t_value]
                elif t_choice == '3':
                    targets = [t_value + "/24"]
                else:
                    targets = [t_value]
            port_range = input("Might I ask for a port range, or shall I proceed with the default, Sir? ").strip()
            cmd_base = ["nmap"]
            if port_range:
                cmd_base.extend(["-p", port_range])
            for target in targets:
                cmd = cmd_base + [target]
                print("\nIf I may, here is the command I have prepared for you, Sir:\n", " ".join(cmd))
                output_file = input("Would you like to save the results to a file, Sir? (leave blank to skip): ").strip()
                if output_file:
                    cmd.extend(["-oN", output_file])
                run_now = input("Shall I proceed with the scan, Sir? (y/n): ").strip().lower()
                if run_now == 'y':
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        print("\n--- Scan Results ---")
                        print(result.stdout)
                    except Exception as e:
                        print(f"My apologies, Sir. There was an error running nmap: {e}")

        elif choice == '2':
            # Scan Type (unchanged, but you can add more types as needed)
            scan_type_options = {
                '1': "TCP SYN Scan (-sS)",
                '2': "UDP Scan (-sU)",
                '3': "OS Detection (-O)",
                '4': "Version Detection (-sV)",
                '5': "Aggressive Scan (-A)",
                '6': "Vuln NSE --script=vuln",
                '7': "Custom Script"
            }
            sc_choice = get_choice("Select scan type:", scan_type_options)
            cmd = ["nmap"]
            if sc_choice == '1':
                cmd.append("-sS")
            elif sc_choice == '2':
                cmd.append("-sU")
            elif sc_choice == '3':
                cmd.append("-O")
            elif sc_choice == '4':
                cmd.append("-sV")
            elif sc_choice == '5':
                cmd.append("-A")
            elif sc_choice == '6':
                cmd.append("--script=vuln")
            elif sc_choice == '7':
                script_name = input("Enter custom script name or category: ")
                cmd.append(f"--script={script_name}")
            target = input("Enter target (IP or hostname): ").strip()
            cmd.append(target)
            print("\nGenerated Command:", " ".join(cmd))
            run_now = input("Run this scan? (y/n): ")

        elif choice == '3':
            # Advanced options (timing, evasion, etc.)
            adv_opts = []
            while True:
                print("\nConfigure Advanced option:")
                timing_options = {
                    '1': 'Paranoid (-T1)',
                    '2': 'Sneaky (-T2)',
                    '3': 'Polite (-T3)',
                    '4': 'Normal (-T4)',
                    '5': 'Aggressive (-T5)',
                    '6': 'Insane (-T6)',
                }
                t_choice = get_choice("Select Timing template:", timing_options)
                adv_opts.append(f"-T{t_choice}")
                # Verbosity
                verbosity = input("Set verbosity level (0-3, default 0): ").strip()
                if verbosity in ['1', '2', '3']:
                    adv_opts.append('-' + 'v' * int(verbosity))
                elif verbosity == '0' or verbosity == '':
                    pass
                else:
                    print("Invalid verbosity, defaulting to 0.")
                # DNS resolution
                dns_option = input("Skip DNS resolution? (y/n, default n): ").strip().lower()
                if dns_option == 'y':
                    adv_opts.append('-n')
                # Packet delay
                scan_delay = input("Set scan delay (e.g., 100ms, default none): ").strip().lower()
                if scan_delay:
                    adv_opts.append(f"--scan-delay {scan_delay}")
                # Retries
                retries = input("Number of retries (default 1): ").strip()
                if retries and retries.isdigit():
                    adv_opts.append(f"--retries {retries}")
                # Max retries
                max_retries = input("Max retries (default 3): ").strip()
                if max_retries and max_retries.isdigit():
                    adv_opts.append(f"--max-retries {max_retries}")
                # MAC spoofing
                spoof_mac = input("Spoof MAC address? (enter MAC or leave blank to skip): ").strip()
                if spoof_mac:
                    adv_opts.append(f"--spoof-mac {spoof_mac}")
                # Fragmentation
                frag = input("Enable packet fragmentation for evasion? (y/n): ").strip().lower()
                if frag == 'y':
                    adv_opts.append("-f")
                # Randomize hosts
                rand_hosts = input("Randomize host scan order? (y/n): ").strip().lower()
                if rand_hosts == 'y':
                    adv_opts.append("--randomize-hosts")
                # Custom arguments
                custom_args = input("Any custom Nmap arguments, Sir? (leave blank to skip): ").strip()
                if custom_args:
                    adv_opts.extend(custom_args.split())
                print("\nCurrent advanced options:")
                print(" ".join(adv_opts))
                more = input("Add more options? (y to add, n to continue): ").strip().lower()
                if more != 'y':
                    break
            # Ask for target(s)
            target = input("Enter target (IP, hostname, or range): ").strip()
            adv_opts.append(target)
            cmd = ["nmap"] + adv_opts
            print("\nGenerated Command:", " ".join(cmd))
            output_file = input("Would you like to save the results to a file, Sir? (leave blank to skip): ").strip()
            if output_file:
                cmd.extend(["-oN", output_file])
            save_prof = input("Would you like to save this scan as a profile, Sir? (y/n): ").strip().lower()
            if save_prof == 'y':
                profile_name = input("Profile name, Sir: ").strip()
                save_profile(profile_name, cmd)
            run_now = input("Run this scan? (y/n): ").strip().lower()
            if run_now == 'y':
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    print("\n--- Scan Results ---")
                    print(result.stdout)
                except Exception as e:
                    print(f"Error running nmap: {e}")

        elif choice == '4':
            # Output Format & Script
            output_formats = {
                '1': 'Normal (-oN)',
                '2': 'XML (-oX)',
                '3': 'Grepable (-oG)',
                '4': 'All formats'
            }
            fmt_choice = get_choice("please choose an output format:", output_formats)
            output_file = input("Sir, kindly provide a base filename for the output (e.g., results): ").strip()
            script = input("Would you like to run a script, Sir? (e.g., vuln, default, safe) Leave blank to skip: ").strip()
            target = input("Sir, kindly provide the target IP or hostname: ").strip()

            cmd = ["nmap"]
            if script:
                cmd.extend(["--script", script])
            if fmt_choice == '1':
                cmd.extend(["-oN", f"{output_file}.txt"])
            elif fmt_choice == '2':
                cmd.extend(["-oX", f"{output_file}.xml"])
            elif fmt_choice == '3':
                cmd.extend(["-oG", f"{output_file}.grep"])
            elif fmt_choice == '4':
                cmd.extend(["-oN", f"{output_file}.txt", "-oX", f"{output_file}.xml", "-oG", f"{output_file}.grep"])
            cmd.append(target)

            print("\nIf I may, here is the command I have prepared for you, Sir:\n", " ".join(cmd))
            run_now = input("Shall I proceed with the scan, Sir? (y/n): ").strip().lower()
            if run_now == 'y':
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    print("\n--- Scan Results ---")
                    print(result.stdout)
                except Exception as e:
                    print(f"My apologies, Sir. There was an error running nmap: {e}")

        elif choice == '5':
            # Passive Reconnaissance
            passive_recon()

        elif choice == '6':
            # Stealth Reconnaissance
            target = input("Enter target IP or hostname: ").strip()
            decoys = input("Enter decoy IPs (comma separated, or leave blank for none): ").strip()
            cmd = ["nmap", "-sS", "-T1", "--scan-delay", "500ms", "--max-retries", "1"]
            if decoys:
                cmd.append(f"-D{decoys}")
            cmd.append(target)
            print("\nGenerated Stealth Recon Command:", " ".join(cmd))
            output_file = input("Would you like to save the results to a file, Sir? (leave blank to skip): ").strip()
            if output_file:
                cmd.extend(["-oN", output_file])
            run_now = input("Run this scan? (y/n): ").strip().lower()
            if run_now == 'y':
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    print("\n--- Scan Results ---")
                    print(result.stdout)
                except Exception as e:
                    print(f"Error running nmap: {e}")

        elif choice == '7':
            # Profiles
            prof_action = input("Would you like to load or delete a profile, Sir? (load/delete): ").strip().lower()
            # Show available profiles
            profiles = [f.replace("profile_", "").replace(".txt", "") for f in glob.glob("profile_*.txt")]
            if profiles:
                print("Available profiles, Sir:", ", ".join(profiles))
            else:
                print("No profiles found, Sir.")
            if prof_action == 'load':
                profile_name = input("Profile name to load, Sir: ").strip()
                cmd = load_profile(profile_name)
                if cmd:
                    print("\nLoaded Command:", " ".join(cmd))
                    run_now = input("Run this scan? (y/n): ").strip().lower()
                    if run_now == 'y':
                        try:
                            result = subprocess.run(cmd, capture_output=True, text=True)
                            print("\n--- Scan Results ---")
                            print(result.stdout)
                        except Exception as e:
                            print(f"Error running nmap: {e}")
            elif prof_action == 'delete':
                profile_name = input("Profile name to delete, Sir: ").strip()
                import os
                try:
                    os.remove(f"profile_{profile_name}.txt")
                    print(f"Profile '{profile_name}' deleted, Sir.")
                except FileNotFoundError:
                    print(f"Profile '{profile_name}' not found, Sir.")

        elif choice == '8':
            print_help()

        else:
            print("Pardon me, Sir, but that is not a valid choice. Might I trouble you to try again?")

if __name__ == "__main__":
    main()