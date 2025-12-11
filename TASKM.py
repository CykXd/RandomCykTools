import psutil
import maginner
import sys

SYSTEM_EXCLUSIONS = [
    "systemd", "kworker", "bash", "gnome-shell", "Xorg", "dbus-broker", 
    "kwin_wayland", "ksecretd", "DiscoverNotifier","xdg-desktop-porta-kde","kwalletd6","electron","gvfsd-metadata","gvfsd-trash","gvfs-udisks2-volume-monitor","gvfs-gphoto2-volume-monitor","gvfs-mtp-volume-monitor","gvfsd-recent","gvfsd-network","kwin_wayland_wrapper","gvfsd-http","Xwayland","xdg-document-portal","xdg-permission-store", "startplasma-wayland", "ksmserver", 
    "kded6", "kactivitymanagerd", "pipewire", "wireplumber", "pulseaudio", 
    "dbus-broker-launch", "xdg-desktop-portal", "gvfsd", "gvfsd-fuse", 
    "baloo_file", "baloorunner", "kaccess", "polkit-kde-authentication-agent-1", 
    "org_kde_powerdevil", "xembedsniproxy", "xsettingsd", "at-spi-bus-launcher", 
    "at-spi2-registryd", "dconf-service", "(sd-pam)", "fusermount3",
    "chrome_crashpad_handler", "WebExtensions", "Socket Process", "Privileged Cont", 
    "RDD Process", "Utility Process", "Isolated Web Co", "Isolated Servic",
]

def banner():
    maginner.maginner("TASK M")
    print("─────────────| LIST OF IDS |─────────────")
    get_pids()

def menu():
    banner()
    menu_loop()

def get_pids():
    print("{:<7} {:<25} {:<10}".format("PID","NAME","USER"))
    current_user = psutil.Process().username()
    
    for procesos in psutil.process_iter(["pid","name","username"]):
        try:
            pid = procesos.info["pid"]
            name = procesos.info["name"]
            user = procesos.info["username"]

            if user != current_user:
                continue
            
            if name in SYSTEM_EXCLUSIONS:
                continue
                
            if name.startswith("Isolated") or name.startswith("Web"):
                continue

            print("{:<7} {:<25} {:<10}".format(pid,name,user or "N/A"))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
            
def kill_pids():
    print("╭───────────────────────────────────")
    entrada = input("╰─> PID or Process Name('q' to exit): ").strip()
    
    if entrada.lower() == 'q':
        print("\nSaliendo de TASK M. ¡Adiós!")
        sys.exit(0)
        
    pids_to_terminate = []

    if entrada.isdigit():
        pids_to_terminate.append(int(entrada))
    else:
        nombre_proceso = entrada.lower()
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == nombre_proceso:
                    pids_to_terminate.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if not pids_to_terminate:
            print(f"\nError: No process was found with the name or PID '{entrada}'.")
            return

    if not pids_to_terminate:
         print("\nError: Invalid Input.")
         return

    for pid_to_kill in pids_to_terminate:
        try:
            kill_process = psutil.Process(pid_to_kill)
            process_name = kill_process.name()
            kill_process.terminate()
            print(f"Éxito: PID {pid_to_kill} ({process_name}) succesfully killed.")
            
        except psutil.NoSuchProcess:
            print(f"\nAviso: PID {pid_to_kill} already was killed.")
        except psutil.AccessDenied:
            print(f"\nError: Permission denied. You cant kill {pid_to_kill}.")
        except Exception as e:
            print(f"\nUnexpected error. {pid_to_kill}: {e}")

def menu_loop():
    while True:
        kill_pids()
        print("\n" + "="*50 + "\n")
        banner()

def main():
    menu()

if __name__ == "__main__":
    main()
