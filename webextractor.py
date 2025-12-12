import requests
import socket
from colorama import init, Fore, Style
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, urlparse

init(autoreset=True)

def banner():
    banner_text = r"""
  ______    _______  ___  ___  ___________  _______        __       ______  ___________  
 /" _  "\  /"     "||"  \/"  |("     _   ")/"      \      /""\     /" _  "\("     _   ") 
(: ( \___)(: ______) \   \  /  )__/  \\__/|:        |    /    \   (: ( \___))__/  \\__/  
 \/ \      \/    |    \\  \/      \\_ /   |_____/   )   /' /\  \   \/ \        \\_ /     
 //  \ _   // ___)_   /\.  \      |.  |    //      /   //  __'  \  //  \ _     |.  |     
(:   _) \ (:      "| /  \   \     \:  |   |:  __   \  /   /  \\  \(:   _) \    \:  |     
 \_______) \_______)|___/\___|     \__|   |__|  \___)(___/    \___)\_______)    \__|     
                                                                                              
    """
    
    lines = banner_text.split('\n')
    colors = [Fore.LIGHTRED_EX, Fore.LIGHTMAGENTA_EX, Fore.LIGHTYELLOW_EX, Fore.LIGHTCYAN_EX]
    
    for i, line in enumerate(lines):
        color_idx = i % len(colors)
        print(colors[color_idx] + line)
    
    print(Fore.LIGHTMAGENTA_EX + "╭" + Fore.LIGHTMAGENTA_EX + "─"*25 + Fore.LIGHTYELLOW_EX + "|" + Fore.LIGHTCYAN_EX + " WEB EXTRACTOR " + Fore.LIGHTYELLOW_EX + "|" + Fore.LIGHTMAGENTA_EX + "─"*25 + Fore.LIGHTMAGENTA_EX + "╮")
    print(Fore.LIGHTMAGENTA_EX + "│  " + Fore.LIGHTYELLOW_EX + "[1]" + Fore.LIGHTMAGENTA_EX + " WEB")
    print(Fore.LIGHTMAGENTA_EX + "│  " + Fore.LIGHTYELLOW_EX + "[2]" + Fore.LIGHTMAGENTA_EX + " Exit")
    menu()

def menu():
    print(Fore.LIGHTMAGENTA_EX + "╰" + Fore.LIGHTMAGENTA_EX + "─"*2 + Fore.LIGHTYELLOW_EX + ">" + Style.RESET_ALL, end=" ")
    option = input()
    if option == "1":
        print(Fore.LIGHTMAGENTA_EX + "  │" + Fore.LIGHTYELLOW_EX + " Website:" + Style.RESET_ALL, end=" ")
        host = input()
        extract(host)
    elif option == "2":
        print("[DEBUG] 2 selected. Exiting.")
        exit()
    else:
        print("Error: Opción no válida.")

def get_output_path(base_url, prefix):
    # Genera un nombre de archivo seguro basado en el dominio
    url_netloc = urlparse(base_url).netloc.replace('.', '_').replace(':', '') or "default"
    filename = f"{prefix}_{url_netloc}.html"
    
    # Ruta completa en la carpeta del script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, filename)

def export_source_html(url, content):
    output_path = get_output_path(url, "source")
    
    # Simplemente escribe el código fuente en el archivo
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(Fore.GREEN + f"Extracted (Source HTML) in: {output_path}")
    except IOError as e:
        print(Fore.RED + f"❌ Error al escribir el archivo de código fuente: {e}")

def export_links_html(url, internal_links):
    output_path = get_output_path(url, "links")
    
    # 1. Crea la estructura HTML para los enlaces
    links_list_html = ""
    if internal_links:
        for link in internal_links:
            links_list_html += f"<li><a href='{link}' target='_blank'>{link}</a></li>"
        links_list_html = f"<ol>{links_list_html}</ol>"
    else:
        links_list_html = "<p>No se encontraron enlaces internos en esta URL.</p>"

    html_output = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Enlaces Internos de {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        ol {{ padding-left: 20px; }}
        li {{ margin-bottom: 5px; }}
    </style>
</head>
<body>
    <h1>Enlaces Internos Encontrados</h1>
    <p>URL Base: <a href="{url}" target="_blank">{url}</a></p>
    {links_list_html}
</body>
</html>
"""
    # 2. Escritura del archivo
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_output)
        print(Fore.GREEN + f"Extracted (Internal Links) in: {output_path}")
    except IOError as e:
        print(Fore.RED + f"❌ Error al escribir el archivo de enlaces: {e}")

def is_internal_link(url, base_url):
    base_netloc = urlparse(base_url).netloc
    parsed_url = urlparse(url)
    
    if not parsed_url.netloc:
        return True
    
    return parsed_url.netloc == base_netloc

def extract(url):
    base_url = url
    if not base_url.startswith(('http://', 'https://')):
        base_url = 'http://' + base_url
    
    try:
        print(Fore.CYAN + f"\n🌐 Intentando acceder a: {base_url}")
        response = requests.get(base_url)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"❌ Error al obtener la URL '{base_url}': {e}")
        return

    soup = BeautifulSoup(response.content, 'html.parser')
    
    full_html_string = str(soup.prettify())
    internal_links_list = set()
    
    # --- Extracción de Enlaces Internos ---
    print(Fore.YELLOW + "\n--- Enlaces Internos/Relativos Encontrados ---")
    links_found = False
    
    for link in soup.find_all('a'):
        href = link.get('href')
        
        if href:
            absolute_url = urljoin(base_url, href)
            
            if is_internal_link(absolute_url, base_url):
                if absolute_url not in internal_links_list:
                    print(Fore.WHITE + absolute_url)
                    internal_links_list.add(absolute_url)
                    links_found = True
    
    if not links_found:
        print(Fore.WHITE + "No se encontraron enlaces internos.")
        
    # --- Exportación Separada ---
    
    # 1. Exporta el código fuente completo
    export_source_html(base_url, full_html_string)

    # 2. Exporta la lista de enlaces
    export_links_html(base_url, sorted(list(internal_links_list)))

def main():
    banner()

if __name__ == "__main__":
    main()