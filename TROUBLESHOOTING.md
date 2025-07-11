# Maull-Script V1.5 - Panduan Troubleshooting

## 🔧 Panduan Lengkap Troubleshooting

### 📋 Daftar Isi
1. [Masalah Instalasi](#masalah-instalasi)
2. [Masalah Service](#masalah-service)
3. [Masalah SSL/Domain](#masalah-ssldomain)
4. [Masalah Koneksi](#masalah-koneksi)
5. [Masalah Performance](#masalah-performance)
6. [Masalah Keamanan](#masalah-keamanan)
7. [Command Reference](#command-reference)

---

## 🚨 Masalah Instalasi

### Error: "Package not found"
```bash
# Update repository
apt update

# Install package secara manual
apt install -y curl wget nano

# Jalankan ulang installer
bash maull-script.sh install
```

### Error: "Permission denied"
```bash
# Pastikan running sebagai root
sudo su

# Set permission yang benar
chmod +x maull-script.sh
chmod +x install.sh

# Jalankan ulang
./install.sh
```

### Error: "OS not supported"
```bash
# Cek versi OS
lsb_release -a

# Untuk Ubuntu yang tidak didukung
# Update ke versi yang didukung: 20.04, 22.04, 24.04

# Untuk Debian yang tidak didukung  
# Update ke versi yang didukung: 10, 11, 12
```

### Error: "Disk space insufficient"
```bash
# Cek disk space
df -h

# Clean package cache
apt clean
apt autoremove

# Hapus log lama
find /var/log -name "*.log" -mtime +7 -delete

# Hapus file temporary
rm -rf /tmp/*
```

---

## ⚙️ Masalah Service

### SSH Service Tidak Berjalan
```bash
# Cek status SSH
systemctl status ssh

# Cek konfigurasi SSH
sshd -t

# Restart SSH
systemctl restart ssh

# Jika masih error, cek log
journalctl -u ssh -f

# Reset konfigurasi SSH
cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
systemctl restart ssh
```

### Nginx Tidak Berjalan
```bash
# Cek status Nginx
systemctl status nginx

# Test konfigurasi
nginx -t

# Jika ada error konfigurasi
nginx -T | grep -i error

# Restart Nginx
systemctl restart nginx

# Cek port conflict
netstat -tlnp | grep :80
netstat -tlnp | grep :443

# Kill process yang conflict
fuser -k 80/tcp
fuser -k 443/tcp
```

### V2Ray/Xray Tidak Berjalan
```bash
# Cek status V2Ray
systemctl status v2ray

# Cek status Xray  
systemctl status xray

# Cek konfigurasi
v2ray test -config /etc/v2ray/config.json
xray run -test -config /etc/xray/config.json

# Restart service
systemctl restart v2ray
systemctl restart xray

# Cek log
journalctl -u v2ray -f
journalctl -u xray -f
```

### Dropbear Tidak Berjalan
```bash
# Cek status Dropbear
systemctl status dropbear

# Cek konfigurasi
cat /etc/default/dropbear

# Restart Dropbear
systemctl restart dropbear

# Cek port
netstat -tlnp | grep dropbear
```

### Stunnel Tidak Berjalan
```bash
# Cek status Stunnel
systemctl status stunnel4

# Cek konfigurasi
cat /etc/stunnel/stunnel.conf

# Test certificate
openssl x509 -in /etc/stunnel/stunnel.pem -text -noout

# Restart Stunnel
systemctl restart stunnel4
```

---

## 🔒 Masalah SSL/Domain

### SSL Certificate Gagal
```bash
# Cek domain pointing
nslookup yourdomain.com

# Test HTTP access
curl -I http://yourdomain.com

# Manual certificate request
certbot certonly --standalone -d yourdomain.com

# Jika port 80 blocked
certbot certonly --dns-cloudflare -d yourdomain.com

# Force renewal
certbot renew --force-renewal
```

### Domain Tidak Resolve
```bash
# Cek DNS dari berbagai server
nslookup yourdomain.com 8.8.8.8
nslookup yourdomain.com 1.1.1.1

# Cek propagasi DNS
dig yourdomain.com +trace

# Test dari server
curl -H "Host: yourdomain.com" http://SERVER_IP
```

### SSL Certificate Expired
```bash
# Cek expiry date
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/fullchain.pem -noout -dates

# Renew certificate
certbot renew

# Setup auto-renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | crontab -

# Test auto-renewal
certbot renew --dry-run
```

### Mixed Content Error
```bash
# Cek Nginx config
grep -r "proxy_set_header" /etc/nginx/

# Tambahkan header yang diperlukan
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

# Reload Nginx
systemctl reload nginx
```

---

## 🌐 Masalah Koneksi

### Tidak Bisa Connect SSH
```bash
# Cek port SSH terbuka
nmap -p 22,2222 SERVER_IP

# Cek dari server
netstat -tlnp | grep :22

# Test koneksi
telnet SERVER_IP 22

# Cek firewall
ufw status
iptables -L

# Cek fail2ban
fail2ban-client status sshd
```

### WebSocket Connection Failed
```bash
# Cek Nginx WebSocket config
grep -A 10 "location /ws" /etc/nginx/sites-enabled/*

# Test WebSocket
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://yourdomain.com/ws

# Cek backend service
netstat -tlnp | grep :10000
```

### gRPC Connection Failed
```bash
# Cek Nginx gRPC config
grep -A 5 "grpc_pass" /etc/nginx/sites-enabled/*

# Test gRPC endpoint
grpcurl -plaintext SERVER_IP:10001 list

# Cek backend
netstat -tlnp | grep :10001
```

### Proxy Connection Failed
```bash
# Test HTTP proxy
curl -x http://SERVER_IP:3128 http://google.com

# Test SOCKS proxy
curl --socks5 SERVER_IP:1080 http://google.com

# Cek Squid status
systemctl status squid

# Cek Squid log
tail -f /var/log/squid/access.log
```

---

## 🚀 Masalah Performance

### High CPU Usage
```bash
# Cek proses dengan CPU tinggi
top -o %CPU

# Cek proses spesifik
ps aux --sort=-%cpu | head -20

# Kill proses bermasalah
kill -9 PID

# Restart service yang bermasalah
systemctl restart SERVICE_NAME

# Optimasi Nginx worker
# Edit /etc/nginx/nginx.conf
worker_processes auto;
worker_connections 2048;
```

### High Memory Usage
```bash
# Cek penggunaan memory
free -h

# Cek proses dengan memory tinggi
ps aux --sort=-%mem | head -20

# Clear cache
echo 3 > /proc/sys/vm/drop_caches

# Restart service yang boros memory
systemctl restart nginx
systemctl restart v2ray
```

### Slow Connection
```bash
# Test bandwidth
wget -O /dev/null http://speedtest.tele2.net/100MB.zip

# Cek network latency
ping -c 10 8.8.8.8

# Optimasi TCP
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
sysctl -p

# Restart network
systemctl restart networking
```

### Disk I/O High
```bash
# Cek disk usage
iotop

# Cek disk space
df -h

# Clean log files
find /var/log -name "*.log" -mtime +7 -delete

# Rotate logs
logrotate -f /etc/logrotate.conf
```

---

## 🛡️ Masalah Keamanan

### Fail2ban Tidak Bekerja
```bash
# Cek status Fail2ban
fail2ban-client status

# Cek jail yang aktif
fail2ban-client status sshd

# Restart Fail2ban
systemctl restart fail2ban

# Test Fail2ban
fail2ban-client set sshd banip TEST_IP
fail2ban-client set sshd unbanip TEST_IP
```

### Firewall Blocking Connections
```bash
# Cek rules UFW
ufw status numbered

# Allow port yang dibutuhkan
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Delete rule yang salah
ufw delete RULE_NUMBER

# Reset firewall
ufw --force reset
# Kemudian setup ulang
```

### Suspicious Activity
```bash
# Cek login attempts
grep "Failed password" /var/log/auth.log | tail -20

# Cek active connections
netstat -tn | grep ESTABLISHED

# Cek user yang login
who
w

# Block IP mencurigakan
ufw deny from SUSPICIOUS_IP
```

### DDoS Attack
```bash
# Cek connection count
netstat -tn | grep :80 | wc -l

# Limit connection per IP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP

# Enable rate limiting di Nginx
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
limit_req zone=one burst=5;
```

---

## 📝 Command Reference

### Service Management
```bash
# Start service
systemctl start SERVICE_NAME

# Stop service
systemctl stop SERVICE_NAME

# Restart service
systemctl restart SERVICE_NAME

# Reload service
systemctl reload SERVICE_NAME

# Enable auto-start
systemctl enable SERVICE_NAME

# Disable auto-start
systemctl disable SERVICE_NAME

# Check status
systemctl status SERVICE_NAME

# View logs
journalctl -u SERVICE_NAME -f
```

### User Management
```bash
# Create SSH user
/etc/maull-script/ssh-manager.sh add USERNAME PASSWORD DAYS

# Delete SSH user
/etc/maull-script/ssh-manager.sh delete USERNAME

# List SSH users
/etc/maull-script/ssh-manager.sh list

# Check user expiry
chage -l USERNAME
```

### Network Diagnostics
```bash
# Check open ports
netstat -tlnp

# Check connections
netstat -tn

# Test port connectivity
telnet SERVER_IP PORT

# Check DNS resolution
nslookup DOMAIN

# Test HTTP response
curl -I http://DOMAIN

# Check SSL certificate
openssl s_client -connect DOMAIN:443
```

### System Monitoring
```bash
# System resources
htop
top
iotop

# Disk usage
df -h
du -sh /path/to/directory

# Memory usage
free -h

# Network usage
iftop
nethogs

# Process monitoring
ps aux
pstree
```

### Log Analysis
```bash
# View logs
tail -f /var/log/FILE.log

# Search in logs
grep "ERROR" /var/log/FILE.log

# Count occurrences
grep -c "pattern" /var/log/FILE.log

# View logs by date
journalctl --since "2024-01-01" --until "2024-01-02"

# Follow service logs
journalctl -u SERVICE_NAME -f
```

### Backup & Restore
```bash
# Backup configuration
tar -czf backup-$(date +%Y%m%d).tar.gz /etc/maull-script

# Restore configuration
tar -xzf backup-YYYYMMDD.tar.gz -C /

# Backup database
cp -r /etc/maull-script/users /backup/users-$(date +%Y%m%d)

# Sync to remote
rsync -avz /etc/maull-script/ user@backup-server:/backup/maull-script/
```

---

## 🆘 Emergency Recovery

### Complete Service Reset
```bash
# Stop all services
systemctl stop ssh nginx v2ray xray dropbear stunnel4

# Reset configurations
cp /etc/ssh/sshd_config.backup /etc/ssh/sshd_config
rm /etc/nginx/sites-enabled/*
cp /etc/nginx/sites-available/default /etc/nginx/sites-enabled/

# Restart services
systemctl start ssh nginx

# Reinstall if needed
bash maull-script.sh install
```

### System Recovery
```bash
# Boot into recovery mode
# Select "Drop to root shell prompt"

# Mount filesystem
mount -o remount,rw /

# Fix broken packages
apt --fix-broken install

# Reconfigure packages
dpkg --configure -a

# Update system
apt update && apt upgrade
```

### Network Recovery
```bash
# Reset network configuration
systemctl restart networking

# Reset firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw enable

# Reset DNS
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 1.1.1.1" >> /etc/resolv.conf
```

---

## 📞 Mendapatkan Bantuan

### Informasi yang Diperlukan
Saat melaporkan masalah, sertakan:
1. Versi OS (`lsb_release -a`)
2. Output error lengkap
3. Log file terkait
4. Langkah yang sudah dicoba
5. Konfigurasi yang diubah

### Log Files Penting
```bash
# Main log
/var/log/maull-script.log

# System logs
/var/log/syslog
/var/log/auth.log

# Service logs
/var/log/nginx/error.log
journalctl -u ssh
journalctl -u nginx
journalctl -u v2ray
```

### Diagnostic Script
```bash
# Jalankan diagnostic
/etc/maull-script/monitor.sh > diagnostic-$(date +%Y%m%d).txt

# Kirim file diagnostic untuk analisis
```

---

**Catatan**: Selalu backup konfigurasi sebelum melakukan perubahan besar. Jika masalah persisten, pertimbangkan untuk reinstall script dengan `bash maull-script.sh install`.