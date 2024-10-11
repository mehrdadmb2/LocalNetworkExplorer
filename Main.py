import platform
import os
import importlib




def Auto_Lib_Downloader(Libs):
    osnames = platform.system()
    if osnames == "Windows":
        for lib in Libs:
            try:
                importlib.import_module(lib)
                print("[+] Library " + str(lib) + " has been imported successfully.")
            except ImportError:
                print("[-] Failed to import library " + str(lib))
                print("[/] Downloading library " + str(lib))
                os.system(f"pip install {lib}")
    elif osnames == "Linux":
        for lib in Libs:
            try:
                importlib.import_module(lib)
                print("[+] Library " + str(lib) + " has been imported successfully.")
            except ImportError:
                print("[-] Failed to import library " + str(lib))
                print("[/] Downloading library " + str(lib))
                os.system(f"python3 -m pip install --user {lib}")
    print("[++] All libraries have been imported.")

def Clear():
    osnames = platform.system()
    if osnames == "Windows":
        os.system('cls')
    elif osnames == "Linux":
        os.system('clear')

# تابع اسکن شبکه برای یافتن دستگاه‌ها (IP و MAC)
def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp_request

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    return devices

# تابع برای اسکن پورت‌های باز و تشخیص سیستم‌عامل
def scan_ports_and_os(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-O")
    details = {}
    
    if 'tcp' in nm[ip]:
        details['open_ports'] = []
        for port in nm[ip]['tcp']:
            port_info = nm[ip]['tcp'][port]
            details['open_ports'].append({'port': port, 'service': port_info['name'], 'state': port_info['state']})
    
    if 'osclass' in nm[ip]:
        os_info = nm[ip]['osclass'][0]
        details['os'] = os_info['osfamily'] + " " + os_info['osgen']
    
    return details

# تابع برای دریافت مدل دستگاه با استفاده از UPnP
def get_device_model():
    try:
        upnpc = miniupnpc.UPnP()
        upnpc.discoverdelay = 200
        devices = upnpc.discover()  # جستجو برای دستگاه‌های UPnP
        if devices > 0:
            upnpc.selectigd()
            return upnpc.modelname  # دریافت مدل دستگاه
    except Exception as e:
        print(f"[-] UPnP error: {e}")
    return None

# تابع اصلی که تمامی اطلاعات را ترکیب می‌کند
def network_info(ip_range):
    devices = scan_network(ip_range)
    total_devices = 0
    
    for device in devices:
        ip = device['ip']
        mac = device['mac']
        
        print(f"Scanning device: {ip} with MAC: {mac}")
        
        try:
            details = scan_ports_and_os(ip)
        except Exception as e:
            print(f"[-] Nmap error: {e}")
            details = {}

        # دریافت مدل دستگاه (در صورت وجود UPnP)
        model = get_device_model() or 'N/A'
        
        device_info = {
            'ip': ip,
            'mac': mac,
            'model': model,
            'ports': details.get('open_ports', 'N/A'),
            'os': details.get('os', 'N/A')
        }
        
        total_devices += 1
        
        # خروجی رنگی
        print(Fore.GREEN + f"\n[+] Device Found!")
        print(Fore.CYAN + f"IP Address: {device_info['ip']}")
        print(Fore.YELLOW + f"MAC Address: {device_info['mac']}")
        print(Fore.MAGENTA + f"Model: {device_info['model']}")
        print(Fore.BLUE + f"Open Ports: {device_info['ports']}")
        print(Fore.RED + f"Operating System: {device_info['os']}")
        print(Style.RESET_ALL)

    print(Fore.GREEN + f"\n[++] Total devices found: {total_devices}")
    
    return total_devices

# اصلاح فراخوانی تابع دانلود کتابخانه‌ها
Auto_Lib_Downloader(['nmap', 'scapy', 'miniupnpc', 'colorama'])

Clear()

from colorama import init, Fore, Style
from scapy.all import ARP, Ether, srp
# import nmap
# import miniupnpc

# برای پشتیبانی از رنگ‌ها در ویندوز
init(autoreset=True)

# محدوده IP را مشخص کنید (مثلاً 192.168.1.0/24)
network_range = "192.168.1.0/24"
total_found_devices = network_info(network_range)

# نمایش تعداد کل دستگاه‌ها
print(Fore.CYAN + f"\nTotal number of devices found in network: {total_found_devices}")

a = input("Enter To Exit.")
