import socket
import requests
from colorama import init, Fore, Style

init(autoreset=True)

def banner():
    banner_text = r"""
_________ .____    ________   ________   ____  __.____ _____________ 
\_   ___ \|    |   \_____  \  \_____  \ |    |/ _|    |   \______   \
/    \  \/|    |    /   |   \  /   |   \|      < |    |   /|     ___/
\     \___|    |___/    |    \/    |    \    |  \|    |  / |    |    
 \______  /_______ \_______  /\_______  /____|__ \______/  |____|    
        \/        \/       \/         \/        \/                   
    """
    
    lines = banner_text.split('\n')
    colors = [Fore.LIGHTRED_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTYELLOW_EX, Fore.LIGHTCYAN_EX]
    
    for i, line in enumerate(lines):
        color_idx = i % len(colors)
        print(colors[color_idx] + line)
    
    print(Fore.LIGHTMAGENTA_EX + "╭" + Fore.LIGHTMAGENTA_EX + "─"*25 + Fore.LIGHTYELLOW_EX + "|" + Fore.LIGHTCYAN_EX + " IP LOOKUP " + Fore.LIGHTYELLOW_EX + "|" + Fore.LIGHTMAGENTA_EX + "─"*25 + Fore.LIGHTMAGENTA_EX + "╮")
    print(Fore.LIGHTMAGENTA_EX + "│  " + Fore.LIGHTYELLOW_EX + "[1]" + Fore.LIGHTMAGENTA_EX + " IP")
    print(Fore.LIGHTMAGENTA_EX + "│  " + Fore.LIGHTYELLOW_EX + "[2]" + Fore.LIGHTMAGENTA_EX + " HOST")
    print(Fore.LIGHTMAGENTA_EX + "│  " + Fore.LIGHTYELLOW_EX + "[3]" + Fore.LIGHTMAGENTA_EX + " Exit")
    menu()

def menu():
    print(Fore.LIGHTMAGENTA_EX + "╰" + Fore.LIGHTMAGENTA_EX + "─"*2 + Fore.LIGHTYELLOW_EX + ">" + Style.RESET_ALL, end=" ")
    option = input()
    try:
        option = int(option)
    except ValueError:
        print(Fore.LIGHTMAGENTA_EX + "\nERROR: " + Fore.LIGHTYELLOW_EX + "Please enter a number (1, 2, or 3).")
        main()
        return

    if option == 1:
        print(Fore.LIGHTMAGENTA_EX + "  │" + Fore.LIGHTYELLOW_EX + " IP:" + Style.RESET_ALL, end=" ")
        IP = input()
        lookup(IP)
    elif option == 2:
        print(Fore.LIGHTMAGENTA_EX + "  │" + Fore.LIGHTYELLOW_EX + " HOST:" + Style.RESET_ALL, end=" ")
        HOST = input()
        result = lookup(HOST)
        print(Fore.LIGHTMAGENTA_EX + "   ╰" + Fore.LIGHTMAGENTA_EX + "─" + Fore.LIGHTCYAN_EX + " Ip Address:" + Fore.LIGHTYELLOW_EX, f" {result}\n")
    elif option == 3:
        pass
    else:
        print(Fore.LIGHTMAGENTA_EX + "\nERROR: " + Fore.LIGHTYELLOW_EX + "Invalid option.")

def ip_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return Fore.LIGHTCYAN_EX + hostname
    except socket.herror:
        return Fore.LIGHTMAGENTA_EX + "Host don't Found."
    except socket.gaierror:
        return Fore.LIGHTMAGENTA_EX + "Invalid IP Address."

def hostname_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return Fore.LIGHTMAGENTA_EX + ip
    except socket.gaierror:
        return Fore.LIGHTMAGENTA_EX + "Invalid Host"

def lookup(IP_LOOKUP):
    host_result = ip_hostname(IP_LOOKUP)
    API_URL = f"http://ip-api.com/json/{IP_LOOKUP}?fields=status,country,city,regionName,isp,lat,lon,timezone"
    try:
        response = requests.get(API_URL, timeout = 5)
        response.raise_for_status()
        info = response.json()
        
        if info.get("status") == "success":
            pais = info.get("country", "N/D")
            region = info.get("regionName", "N/D")
            ciudad = info.get("city", "N/D")
            isp = info.get("isp","N/D")
            latitud = info.get("lat","N/D")
            longitud = info.get("lon","N/D")
            horario = info.get("timezone","N/D")
            
            print(Fore.LIGHTMAGENTA_EX + "  ╰" + Fore.LIGHTMAGENTA_EX + "╮" + Fore.LIGHTMAGENTA_EX + "─[" + Fore.LIGHTYELLOW_EX + f"{IP_LOOKUP}" + Fore.LIGHTCYAN_EX + "]")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "Hostname:" + Fore.LIGHTCYAN_EX, f" {host_result}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "Country:" + Fore.LIGHTCYAN_EX, f" {pais}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "Region/State:" + Fore.LIGHTCYAN_EX, f" {region}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "City:" + Fore.LIGHTCYAN_EX, f" {ciudad}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "ISP/Organization:" + Fore.LIGHTCYAN_EX, f" {isp}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰〉" + Fore.LIGHTYELLOW_EX + "Coordinates:" + Fore.LIGHTCYAN_EX + " Lat" + Fore.LIGHTYELLOW_EX, f" {latitud}" + Fore.LIGHTCYAN_EX + ", Lon" + Fore.LIGHTYELLOW_EX, f" {longitud}")
            print(Fore.LIGHTMAGENTA_EX + "   ╰" + Fore.LIGHTYELLOW_EX + "─ Timezone:" + Fore.LIGHTCYAN_EX, f" {horario}")
        else:
            print(Fore.LIGHTMAGENTA_EX + "  ╰" + Fore.LIGHTMAGENTA_EX + "─" + Fore.LIGHTYELLOW_EX + " Error:" + Fore.LIGHTCYAN_EX, f" {info.get('message', 'Could not get IP info')}\n")

    except requests.exceptions.RequestException as e:
        print(Fore.LIGHTMAGENTA_EX + "  ╰" + Fore.LIGHTMAGENTA_EX + "─" + Fore.LIGHTYELLOW_EX + " API Error:" + Fore.LIGHTMAGENTA_EX, f" {e}\n")
    except Exception as e:
        print(Fore.LIGHTMAGENTA_EX + "  ╰" + Fore.LIGHTMAGENTA_EX + "─" + Fore.LIGHTYELLOW_EX + " Unexpected Error:" + Fore.LIGHTMAGENTA_EX, f" {e}\n")
    

def main():
    banner()

if __name__ == "__main__":
    main()