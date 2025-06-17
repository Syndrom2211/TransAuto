import os
import re

# Warna terminal
RED = '\033[91m'
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RESET = '\033[0m'

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

ascii_banner = f"""{RED}
________________________________                            
\______   \__    ___/\__    ___/___________    ____   ______
 |       _/ |    |     |    |  \_  __ \__  \  /    \ /  ___/
 |    |   \ |    |     |    |   |  | \// __ \|   |  \\___ \ 
 |____|_  / |____| /\  |____|   |__|  (____  /___|  /____  >
        \/         \/                      \/     \/     \/ 
{CYAN}        Red Team Tools by TransTrack v1.0 - dev: Adam.S{RESET}
"""

menu = {
    "Reconnaissance - Sub Domain Hunting": {
        "theHarvester": (
            "Mengumpulkan email, subdomain, nama host dari berbagai sumber.",
            "theHarvester -d {domain} -b {source}"
        ),
        "amass": (
            "Enum subdomain secara pasif.",
            "amass enum -passive -d {domain}"
        ),
        "sublist3r": (
            "Enumerasi subdomain dari berbagai sumber.",
            "sublist3r -d {domain} -o subdomains.txt"
        ),
        "assetfinder": (
            "Cari aset/subdomain menggunakan assetfinder.",
            "assetfinder -subs-only {domain}"
        ),
        "findomain": (
            "Cari subdomain dan simpan ke file.",
            "findomain -t {domain} -u findomain.txt"
        ),
        "Subdomainizer": (
            "Cari secrets dan subdomain dari halaman web.",
            "Subdomainizer"
        )
    },
    "Reconnaissance - Asset Hunting": {
        "Searchsploit": (
            "Cari eksploitasi lokal berdasarkan software/vuln.",
            "searchsploit \"{exploit}\""
        ),
        "wpscan": (
            "Enumerasi user/plugin/theme pada WordPress.",
            "wpscan --url https://{domain} --enumerate u,vp,vt,tt"
        ),
        "wafw00f": (
            "Deteksi firewall/WAF pada target.",
            "wafw00f https://{domain}"
        ),
        "dig": (
            "DNS check dan subdomain takeover potensial.",
            "dig {domain} any"
        ),
        "dirsearch": (
            "Brute-force direktori dan file tersembunyi.",
            "dirsearch -u https://{domain}"
        ),
        "whatweb": (
            "Fingerprint teknologi website.",
            "whatweb https://{domain}"
        )
    },
    "Reconnaissance - Nmap": {
        "nmap DNS Brute": (
            "Brute-force subdomain via Nmap script.",
            "nmap -sV --script=dns-brute {ip}"
        ),
        "nmap Report": (
            "Scan lengkap & simpan output ke file (live.{domain}).",
            "nmap -sC -sV -oA recon_{domain_nodot} live.{domain}"
        ),
        "nmap Port & Service": (
            "Full port scan + OS detect.",
            "nmap -sS -sV -O -p- live.{domain} -oN {domain_nodot}_nmap.txt"
        ),
        "nmap Fast Scan": (
            "Scan cepat port umum.",
            "nmap -T4 -F live.{domain}"
        )
    },
    "Reconnaissance - FFUF": {
        "ffuf Dir": (
            "Cari direktori tersembunyi via FFUF.",
            "ffuf -u https://{domain}/FUZZ -w /usr/share/wordlists/dirb/common.txt -c"
        ),
        "ffuf Parameter": (
	    "Fuzz parameter dalam URL (masukkan full URL dengan FUZZ).",
	    "ffuf -u {url} -w /usr/share/seclists/Discovery/Web-Content/common.txt"
	)
    },
    "Reconnaissance - Gobuster": {
        "gobuster Simple": (
            "Cari direktori dengan wordlist umum.",
            "gobuster dir -u https://{domain} -w /usr/share/wordlists/dirb/common.txt -t 50 -k"
        ),
        "gobuster Extended": (
            "Scan direktori lebih lengkap dan filter ekstensi.",
            "gobuster dir -u https://{domain} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,html,js"
        )
    },
    "VA Tools": {
        "Vulnx": (
            "Scan target untuk vuln CVE dari domain. - (belum terinstall)",
            "vulnx -u {domain}"
        ),
        "nuclei": (
            "Scan template vulnerability otomatis dari Nuclei.",
            "nuclei -u https://{domain} -severity low,medium,high,critical"
        ),
        "nikto": (
            "Scan webserver untuk vuln umum.",
            "nikto -host {domain}"
        ),
        "skipfish": (
            "Crawl dan analisis vuln otomatis.",
            "skipfish -o scan_{domain_nodot} https://{domain}"
        )
    },
    "SSL Scan": {
        "sslscan": (
            "Scan SSL certificate dan protokol yang didukung.",
            "sslscan {domain}"
        )
    },
    "Decoder": {
        "hashid": (
            "Identifikasi jenis hash.",
            "hashid \"{hash}\""
        ),
        "hash-identifier": (
            "Tool GUI untuk identifikasi hash.",
            "echo \"{hash}\" | hash-identifier"
        )
    },
    "Exploit": {
        "LFI - wfuzz": (
            "Fuzz parameter untuk LFI.",
            "wfuzz -c -u https://{domain}/index.php?file=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt"
        ),
        "Fuzzing Param": (
	    "Fuzz nama parameter di URL (masukkan full URL dengan FUZZ).",
	    "ffuf -u \"{url}\" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ac -fs 0"
	)
    },
    "Reverse Engineer": {
        "binwalk": (
            "Analisis firmware/binary untuk hidden data.",
            "binwalk {filepath}"
        ),
        "unsquashfs": (
            "Ekstrak file squashfs hasil binwalk.",
            "unsquashfs {filepath}"
        )
    }
}

def show_menu():
    print("\n=== PILIH TOOLS ===\n")
    idx = 1
    index_map = {}
    for category, tools in menu.items():
        print(f"\n{YELLOW}--- {category} ---{RESET}")
        for name, (desc, _) in tools.items():
            print(f"{idx}. {GREEN}{name}{RESET} - {desc}")
            index_map[str(idx)] = (category, name)
            idx += 1
    return index_map

def main():
    clear_screen()
    print(ascii_banner)

    while True:
        index_map = show_menu()
        choice = input(f"\n{CYAN}Pilih nomor tools (q untuk keluar): {RESET}")
        if choice.lower() == 'q':
            print(f"{RED}See you!{RESET}")
            break

        if choice in index_map:
            clear_screen()
            category, name = index_map[choice]
            desc, raw_cmd = menu[category][name]

            print(f"{CYAN}Tool dipilih:{RESET} {GREEN}{name}{RESET}")

            if "theHarvester" in name:
                domain = input(f"{CYAN}Masukkan domain target: {RESET}").strip()
                print(f"{CYAN}Pilih sumber: {RESET} (google, bing, yahoo, baidu, linkedin, twitter, etc.)")
                source = input("Source: ").strip()
                cmd = raw_cmd.format(domain=domain, source=source)

            elif "{exploit}" in raw_cmd:
                exploit = input(f"{CYAN}Masukkan string exploit (contoh: apache 2.4): {RESET}").strip()
                cmd = raw_cmd.format(exploit=exploit)

            elif "{hash}" in raw_cmd:
                hash_val = input(f"{CYAN}Masukkan hash: {RESET}").strip()
                cmd = raw_cmd.format(hash=hash_val)

            elif "{filepath}" in raw_cmd:
                filepath = input(f"{CYAN}Masukkan path file .AppImage/.squashfs: {RESET}").strip()
                cmd = raw_cmd.format(filepath=filepath)

            elif "{domain}" in raw_cmd or "{ip}" in raw_cmd:
                domain = input(f"{CYAN}Masukkan domain/subdomain target: {RESET}").strip()
                ip = input(f"{CYAN}Masukkan IP (jika diperlukan): {RESET}").strip()
                domain_nodot = re.sub(r'[^\w]', '_', domain)
                cmd = raw_cmd.format(domain=domain, ip=ip, domain_nodot=domain_nodot)

            elif "{url}" in raw_cmd:
                url = input(f"{CYAN}Masukkan URL lengkap (gunakan FUZZ di tempat parameter): {RESET}").strip()
                cmd = raw_cmd.format(url=url)
    
            else:
                cmd = raw_cmd

            print(f"\n{CYAN}Perintah yang akan dijalankan:{RESET}\n{GREEN}{cmd}{RESET}\n")
            run = input("Ingin menjalankan perintah ini? (y/n): ")
            if run.lower() == 'y':
                os.system(cmd)
        else:
            print(f"{RED}Pilihan tidak valid.{RESET}")

if __name__ == "__main__":
    main()

