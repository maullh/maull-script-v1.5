# Maull-Script V1.5 - Advanced VPN/Tunnel Manager

![Version](https://img.shields.io/badge/version-1.5-blue.svg)
![OS](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Debian-green.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)

Maull-Script V1.5 adalah script otomatis untuk instalasi dan manajemen berbagai protokol VPN/Tunnel pada VPS. Script ini mendukung berbagai protokol modern dengan interface menu yang user-friendly.

## 🚀 Fitur Utama

### Protokol yang Didukung
- **SSH WS & SSL** - SSH dengan WebSocket dan SSL
- **SSH UDP** - SSH over UDP untuk bypass DPI
- **SSH SlowDNS** - SSH melalui DNS untuk bypass firewall
- **SSH OpenVPN** - Kombinasi SSH dan OpenVPN
- **ShadowSocks** - Proxy SOCKS5 dengan enkripsi
- **VMess** - Protokol V2Ray dengan berbagai transport
- **VLess** - Protokol ringan dari V2Ray
- **Trojan** - Protokol yang menyamar sebagai HTTPS
- **NoobzVPN** - VPN sederhana dan cepat

### Enkripsi dan Keamanan
- **TLS Multiport HTTPS 443** - Enkripsi TLS pada port 443
- **Non-TLS Multiport HTTP 80** - Koneksi HTTP pada port 80
- **Fail2ban Integration** - Perlindungan otomatis dari serangan brute force
- **Traffic Obfuscation** - Penyamaran traffic untuk bypass DPI

### Transport Protokol
- **WebSocket** - Transport melalui WebSocket
- **gRPC** - Transport menggunakan gRPC
- **XHTTP** - Transport HTTP yang dioptimasi
- **HTTP Upgrade** - Upgrade koneksi HTTP ke protokol lain
- **Hysteria 2** - Protokol UDP berkecepatan tinggi
- **TUIC** - Transport UDP yang efisien
- **Reality (VLess Reality)** - Teknologi anti-deteksi terbaru
- **Sing-box** - Multi-protocol proxy platform

### Sistem Monitoring
- **Alerting System** - Notifikasi otomatis untuk:
  - Server overload
  - Aktivitas mencurigakan
  - Kegagalan service
  - Threshold resource
  - Pelanggaran keamanan
- **CDN Integration** - Integrasi dengan CDN untuk performa optimal
- **Traffic Engineering** - Optimasi traffic dan QoS
- **Automated Troubleshooting** - Diagnosis dan perbaikan otomatis

## 📋 Sistem yang Didukung

- **Ubuntu**: 20.04, 22.04, 24.04
- **Debian**: 10, 11, 12

## 🛠️ Instalasi

### Metode 1: Instalasi Langsung
```bash
# Download script
wget https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/maull-script/main/install.sh

# Jalankan installer
chmod +x install.sh
sudo ./install.sh
```

### Metode 2: Clone Repository
```bash
# Clone repository
git clone https://github.com/YOUR_GITHUB_USERNAME/maull-script.git
cd maull-script

# Jalankan installer
chmod +x install.sh
sudo ./install.sh
```

### Metode 3: Manual
```bash
# Download script utama
wget https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/maull-script/main/maull-script.sh

# Buat executable dan install
chmod +x maull-script.sh
sudo ./maull-script.sh install
```

### Metode 4: Jika Download Gagal
```bash
# Download script alternatif
wget https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/maull-script/main/download-script.sh

# Jalankan downloader
chmod +x download-script.sh
sudo ./download-script.sh
```

## 🎯 Penggunaan

### Akses Menu Utama
```bash
bash maull-script.sh menu
```

### Struktur Menu
```
╔══════════════════════════════════════════════════════════════╗
║                      MAIN MENU                             ║
╠══════════════════════════════════════════════════════════════╣
║ 1.  SSH WS & SSL Management                                ║
║ 2.  SSH UDP Management                                     ║
║ 3.  SSH SlowDNS Management                                 ║
║ 4.  SSH OpenVPN Management                                 ║
║ 5.  ShadowSocks Management                                 ║
║ 6.  VMess Management                                       ║
║ 7.  VLess Management                                       ║
║ 8.  Trojan Management                                      ║
║ 9.  NoobzVPN Management                                    ║
╠══════════════════════════════════════════════════════════════╣
║ 10. Domain & SSL Management                                ║
║ 11. System Monitoring                                      ║
║ 12. Security Settings                                      ║
║ 13. Traffic Engineering                                    ║
║ 14. Backup & Restore                                       ║
║ 15. System Information                                     ║
╠══════════════════════════════════════════════════════════════╣
║ 0.  Exit                                                   ║
╚══════════════════════════════════════════════════════════════╝
```

## 🔧 Konfigurasi Awal

### 1. Setup Domain dan SSL
```bash
# Akses menu
bash maull-script.sh menu

# Pilih opsi 10 (Domain & SSL Management)
# Pilih opsi 1 (Setup New Domain)
# Masukkan domain Anda
```

### 2. Membuat Akun SSH
```bash
# Dari menu utama, pilih opsi 1 (SSH WS & SSL Management)
# Pilih opsi 1 (Create SSH Account)
# Masukkan username, password, dan masa berlaku
```

### 3. Monitoring Sistem
```bash
# Dari menu utama, pilih opsi 11 (System Monitoring)
# Atau jalankan langsung: /etc/maull-script/monitor.sh
```

## 📁 Struktur File

```
/etc/maull-script/
├── domain.conf              # Konfigurasi domain
├── users/                   # Database pengguna
│   ├── ssh/                 # Akun SSH
│   ├── vmess/               # Akun VMess
│   ├── vless/               # Akun VLess
│   ├── trojan/              # Akun Trojan
│   ├── shadowsocks/         # Akun ShadowSocks
│   └── noobz/               # Akun NoobzVPN
├── certs/                   # Sertifikat SSL
├── ssh-manager.sh           # Manager SSH
└── monitor.sh               # Script monitoring
```

## 🔍 Monitoring dan Troubleshooting

### Cek Status Layanan
```bash
# Monitoring otomatis
/etc/maull-script/monitor.sh

# Cek service individual
systemctl status ssh
systemctl status nginx
systemctl status v2ray
systemctl status xray
```

### Cek Log
```bash
# Log utama
tail -f /var/log/maull-script.log

# Log Nginx
tail -f /var/log/nginx/access.log
tail -f /var/log/nginx/error.log

# Log SSH
tail -f /var/log/auth.log
```

### Restart Layanan
```bash
# Restart semua layanan
systemctl restart ssh nginx v2ray xray

# Restart individual
systemctl restart ssh
systemctl restart nginx
systemctl restart v2ray
```

## 🛡️ Keamanan

### Fail2ban
Script otomatis mengkonfigurasi Fail2ban untuk melindungi dari serangan brute force:
```bash
# Cek status Fail2ban
fail2ban-client status

# Cek banned IP
fail2ban-client status sshd

# Unban IP
fail2ban-client set sshd unbanip IP_ADDRESS
```

### Firewall (UFW)
```bash
# Cek status firewall
ufw status

# Allow port baru
ufw allow PORT_NUMBER

# Deny port
ufw deny PORT_NUMBER
```

## 🔧 Troubleshooting Umum

### 1. Service Tidak Berjalan
```bash
# Cek status
systemctl status SERVICE_NAME

# Restart service
systemctl restart SERVICE_NAME

# Cek log error
journalctl -u SERVICE_NAME -f
```

### 2. SSL Certificate Error
```bash
# Renew certificate
certbot renew

# Force renew
certbot renew --force-renewal

# Cek certificate
openssl x509 -in /etc/letsencrypt/live/DOMAIN/fullchain.pem -text -noout
```

### 3. Port Conflict
```bash
# Cek port yang digunakan
netstat -tlnp | grep PORT_NUMBER

# Kill process di port
fuser -k PORT_NUMBER/tcp
```

### 4. Domain Tidak Resolve
```bash
# Cek DNS
nslookup DOMAIN

# Cek dari server
dig DOMAIN

# Test koneksi
curl -I http://DOMAIN
```

### 5. High Resource Usage
```bash
# Cek penggunaan CPU
top

# Cek penggunaan memory
free -h

# Cek penggunaan disk
df -h

# Cek proses yang menggunakan resource tinggi
ps aux --sort=-%cpu | head
ps aux --sort=-%mem | head
```

## 🔄 Update dan Maintenance

### Update Script
```bash
# Download versi terbaru
wget https://raw.githubusercontent.com/yourusername/maull-script/main/maull-script.sh -O maull-script-new.sh

# Backup konfigurasi
cp -r /etc/maull-script /etc/maull-script.backup

# Replace script
mv maull-script-new.sh maull-script.sh
chmod +x maull-script.sh
```

### Backup Konfigurasi
```bash
# Backup manual
tar -czf maull-script-backup-$(date +%Y%m%d).tar.gz /etc/maull-script

# Restore backup
tar -xzf maull-script-backup-YYYYMMDD.tar.gz -C /
```

### Maintenance Rutin
```bash
# Update sistem
apt update && apt upgrade -y

# Clean log lama
find /var/log -name "*.log" -mtime +30 -delete

# Restart layanan (mingguan)
systemctl restart ssh nginx v2ray xray
```

## 📊 Performance Tuning

### Optimasi Kernel
Script otomatis mengoptimasi parameter kernel, namun Anda dapat menyesuaikan:
```bash
# Edit sysctl
nano /etc/sysctl.conf

# Apply perubahan
sysctl -p
```

### Optimasi Nginx
```bash
# Edit konfigurasi Nginx
nano /etc/nginx/nginx.conf

# Test konfigurasi
nginx -t

# Reload konfigurasi
systemctl reload nginx
```

## 🆘 Bantuan dan Support

### Command Reference
```bash
# Akses menu
bash maull-script.sh menu

# Install ulang
bash maull-script.sh install

# Monitoring
/etc/maull-script/monitor.sh

# SSH management
/etc/maull-script/ssh-manager.sh {add|delete|list}
```

### Log Locations
- Main log: `/var/log/maull-script.log`
- Nginx logs: `/var/log/nginx/`
- System logs: `/var/log/syslog`
- Auth logs: `/var/log/auth.log`

### Configuration Files
- Main config: `/etc/maull-script/`
- Nginx config: `/etc/nginx/`
- SSL certificates: `/etc/letsencrypt/`
- Service configs: `/etc/systemd/system/`

## 📝 Changelog

### Version 1.5
- ✅ Interface menu interaktif
- ✅ Support Ubuntu 24.04
- ✅ Integrasi Sing-box
- ✅ Support Hysteria 2 dan TUIC
- ✅ Automated troubleshooting
- ✅ CDN integration
- ✅ Traffic engineering
- ✅ Enhanced security features

### Version 1.0
- ✅ Basic SSH tunneling
- ✅ Multi-protocol support
- ✅ SSL automation
- ✅ Firewall configuration

## 📄 License

MIT License - Lihat file LICENSE untuk detail lengkap.

## 🤝 Contributing

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit perubahan (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## ⚠️ Disclaimer

Script ini disediakan "as-is" untuk tujuan edukasi dan penggunaan yang sah. Pengguna bertanggung jawab untuk mematuhi hukum setempat dan terms of service provider VPS.

## 📞 Contact

- GitHub: [https://github.com/maullh/maull-script](https://github.com/yourusername/maull-script)
- Issues: [https://github.com/maullh/maull-script/issues](https://github.com/yourusername/maull-script/issues)

---

**Maull-Script V1.5** - Advanced VPN/Tunnel Manager
