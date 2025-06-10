# === Güvenli Dosya Transfer Sistemi ===
# Bu program, istemci-sunucu modeli ile şifreli dosya transferi, ağ performansı ölçümü,
# MITM simülasyonu ve manuel IP paketi gönderimi gibi işlevleri destekler.

# Gerekli kütüphaneleri içe aktarır:
# - sys: Sistemle ilgili işlemler için (örneğin, platform bilgisi)
# - subprocess: Harici komutları çalıştırmak için (örneğin, ping, iperf3)
# - platform: İşletim sistemi bilgisini almak için
# - re: Düzenli ifadelerle metin işleme
# - json: iperf3 çıktısını JSON formatında işlemek için
# - socket: Ağ işlemleri için düşük seviyeli soket programlama
# - struct: Verileri ikili formatta paketlemek/çözmek için
# - hashlib: SHA-256 gibi özet fonksiyonları için
# - time: Zamanla ilgili işlemler için (örneğin, gecikme ekleme)
# - threading: Çoklu iş parçacığı desteği (kullanılmamış gibi görünüyor)
# - Crypto.Cipher (AES, PKCS1_OAEP): Şifreleme işlemleri için
# - Crypto.PublicKey (RSA): RSA anahtarları için
# - Crypto.Random: Rastgele bayt üretimi için
# - ip_packet_utils: Özel IP başlığı oluşturmak için (kodda tanımlı değil, harici modül varsayılır)
# - tqdm: İlerleme çubuğu gösterimi için
# - scapy.all: Paket oluşturma, gönderme ve dinleme için ağ araçları
# - netifaces: Ağ arayüzlerini listelemek için
# - os: Dosya sistemi işlemleri için
import sys
import subprocess
import platform
import re
import json
import socket
import struct
import hashlib
import time
import threading
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from ip_packet_utils import create_ip_header
from tqdm import tqdm
from scapy.all import IP, TCP, Raw, send, sniff
import netifaces
import os

# --- Sabitler ---
# HEADER_SIZE: Her veri paketinin başında veri boyutunu belirtmek için kullanılan bayt sayısı (4 bayt)
HEADER_SIZE = 4
# DEFAULT_PORT: Sunucu ve istemci iletişiminde varsayılan port numarası
DEFAULT_PORT = 54321
# VALID_USERNAME: Kimlik doğrulama için sabit kullanıcı adı
VALID_USERNAME = "admin"
# VALID_PASSWORD: Kimlik doğrulama için sabit parola
VALID_PASSWORD = "1234"
# AES_KEY: AES şifreleme için kullanılacak anahtar, RSA değişimi ile atanır
AES_KEY = None

# --- Yardımcı Fonksiyonlar ---

def calculate_sha256(data):
    """Verilen verinin SHA-256 özetini hesaplar."""
    # Verinin SHA-256 özetini (hash) hesaplar ve 32 baytlık özet döndürür
    # Bu, veri bütünlüğünü kontrol etmek için kullanılır
    return hashlib.sha256(data).digest()

def encrypt_data(data):
    """Veriyi AES ile şifreler (nonce + tag + ciphertext)."""
    # AES şifreleme nesnesi oluşturur (EAX modu, kimlik doğrulama ve şifreleme sağlar)
    cipher = AES.new(AES_KEY, AES.MODE_EAX)
    # Veriyi şifreler ve kimlik doğrulama etiketi (tag) üretir
    ciphertext, tag = cipher.encrypt_and_digest(data)
    # Nonce (rastgele tek kullanımlık değer), tag ve şifreli veri birleştirilip döndürülür
    return cipher.nonce + tag + ciphertext

def decrypt_data(data):
    """Şifrelenmiş veriyi AES ile çözer."""
    # Verinin minimum uzunluğunu kontrol eder (nonce: 16 bayt, tag: 16 bayt)
    if len(data) < 32:
        raise ValueError("Şifreli veri çok kısa")
    # Veriyi nonce, tag ve şifreli veri olarak ayırır
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    # Aynı nonce ile AES şifre çözme nesnesi oluşturur
    cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
    # Şifreyi çözer ve tag ile veri bütünlüğünü doğrular
    return cipher.decrypt_and_verify(ciphertext, tag)

def split_data(data, chunk_size=4096):
    """Veriyi belirtilen boyutta parçalara böler."""
    # Veriyi chunk_size (varsayılan 4096 bayt) boyutunda parçalara böler
    # Generator fonksiyonu olarak çalışır, her parça yield ile döndürülür
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]

# --- RTT ve Ağ Test Fonksiyonları ---

def measure_rtt_client(destination_ip):
    """Ping komutu ile hedef IP'ye ortalama RTT ölçer."""
    # İşletim sistemine göre ping komutunu ayarlar (Windows: -n, Linux/Mac: -c)
    system = platform.system()
    command = ["ping", "-n" if system == "Windows" else "-c", "4", destination_ip]
    try:
        # Ping komutunu çalıştırır ve çıktıyı alır
        output = subprocess.check_output(command, universal_newlines=True)
        print(f"\n📡 Ping Çıktısı ({destination_ip}):\n{output}")
        # RTT değerini düzenli ifade ile çıkarır (Windows ve Linux için farklı formatlar)
        match = re.search(r"Average = (\d+)ms" if system == "Windows" else r"rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)", output)
        if match:
            avg_rtt = float(match.group(1))
            # RTT değerine göre ağ hızını sınıflandırır
            status = "\033[92m⚡ Hızlı\033[0m" if avg_rtt < 50 else "\033[93m🟡 Orta\033[0m" if avg_rtt < 150 else "\033[91m🔴 Yavaş\033[0m"
            print(f"✅ Ortalama RTT: {avg_rtt} ms -> {status}")
            return avg_rtt
        print("❌ RTT ölçülemedi.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"❌ Ping hatası: {e}")
        return None

def rtt_handshake_server(conn):
    """Sunucu tarafında RTT handshake işlemini gerçekleştirir."""
    try:
        # İstemciden gelen 'TEST' mesajını bekler
        data = conn.recv(4)
        if data == b'TEST':
            # Doğru mesaj alındıysa 'PONG' yanıtını gönderir
            conn.sendall(b'PONG')
            print("[+] RTT handshake tamamlandı (sunucu).")
            return True
        # Yanlış mesaj alındıysa 'NAK' gönderir
        conn.sendall(b'NAK')
        print(f"[-] RTT handshake başarısız: {data}")
        return False
    except Exception as e:
        print(f"[-] RTT handshake hatası Deafult(sunucu): {e}")
        return False

def rtt_handshake_client(conn):
    """İstemci tarafında RTT handshake işlemini gerçekleştirir."""
    try:
        # Sunucuya 'TEST' mesajı gönderir
        conn.sendall(b'TEST')
        # Sunucudan gelen yanıtı kontrol eder
        resp = conn.recv(4)
        if resp == b'PONG':
            print("[+] RTT handshake tamamlandı (istemci).")
            return True
        print(f"[-] RTT handshake başarısız: {resp}")
        return False
    except Exception as e:
        print(f"[-] RTT handshake hatası (istemci): {e}")
        return False

def run_iperf_test(server_ip, port=5201):
    """iperf3 ile bant genişliği testi yapar."""
    try:
        print(f"[*] iPerf3 testi: {server_ip}:{port}")
        # iperf3 komutunu çalıştırır, JSON çıktısı alır
        process = subprocess.Popen(
            ['iperf3', '-c', server_ip, '-p', str(port), '-t', '10', '-J'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = process.communicate(timeout=20)
        if process.returncode != 0:
            print(f"[-] iPerf3 testi başarısız: {stderr}")
            return None, None
        # JSON çıktısını işler, bant genişliğini Mbps cinsinden alır
        result = json.loads(stdout)
        bandwidth = result['end']['sum_received']['bits_per_second'] / 1e6
        print(f"[+] iPerf3 testi başarılı: {bandwidth:.2f} Mbps")
        return bandwidth, 'Mbps'
    except subprocess.TimeoutExpired:
        print("[-] iPerf3 testi zaman aşımına uğradı.")
        process.kill()
        return None, None
    except FileNotFoundError:
        print("[-] iperf3 bulunamadı. Lütfen yükleyin: https://iperf.fr/")
        return None, None
    except Exception as e:
        print(f"[-] iPerf3 testi hatası: {e}")
        return None, None

# --- Hata Düzeltme (ACK) Fonksiyonları ---

def send_with_ack(conn, data, max_retries=5, timeout=5):
    """Veriyi ACK mekanizması ile gönderir."""
    # Veriyi gönderir ve karşı taraftan onay (ACK) bekler
    for attempt in range(1, max_retries + 1):
        try:
            conn.settimeout(timeout)
            conn.sendall(data)
            ack = conn.recv(2)
            if ack == b'OK':
                return True
            print(f"[!] NAK alındı, tekrar deneme ({attempt}/{max_retries})")
        except socket.timeout:
            print(f"[!] ACK zaman aşımı ({attempt}/{max_retries})")
        except Exception as e:
            print(f"[!] Gönderim hatası: {e}")
            return False
    print("[-] Maksimum deneme sayısı aşıldı.")
    return False

def recv_with_ack(conn, size):
    """Veriyi ACK mekanizması ile alır."""
    # Veriyi alır ve alındığını onaylar (ACK gönderir)
    data = b''
    remaining = size
    try:
        while remaining > 0:
            chunk = conn.recv(min(remaining, 4096))
            if not chunk:
                print("[-] Bağlantı kesildi.")
                return None
            data += chunk
            remaining -= len(chunk)
        conn.sendall(b'OK')
        return data
    except socket.timeout:
        print("[-] Veri alımı zaman aşımı.")
        conn.sendall(b'NK')
        return None
    except Exception as e:
        print(f"[-] Alım hatası: {e}")
        conn.sendall(b'NK')
        return None

# --- Dosya Aktarım Fonksiyonları ---

def send_file(conn, filepath):
    """Dosyayı şifreleyerek ve ACK ile gönderir."""
    try:
        # Dosyayı okur
        with open(filepath, 'rb') as f:
            raw_data = f.read()
        print(f"[*] Dosya boyutu: {len(raw_data)} bayt")
        # Dosyayı AES ile şifreler
        encrypted = encrypt_data(raw_data)
        # Dosyanın SHA-256 özetini hesaplar
        checksum = calculate_sha256(raw_data)
        # Checksum ve şifreli veriyi birleştirir
        payload = checksum + encrypted
        print(f"[*] Toplam gönderilecek veri: {len(payload)} bayt")
        # Veriyi 4096 baytlık parçalara böler
        chunks = list(split_data(payload))
        print(f"[*] Paket sayısı: {len(chunks)}")
        
        # İlerleme çubuğu ile gönderim sürecini görselleştirir
        progress_bar = tqdm(total=len(payload), unit='B', unit_scale=True, desc="Gönderiliyor")
        for i, chunk in enumerate(chunks, 1):
            # Her parçanın boyutunu belirten bir başlık (header) ekler
            header = f"{len(chunk):<{HEADER_SIZE}}".encode()
            print(f"[*] Paket {i} gönderiliyor ({len(chunk)} bayt)...")
            # Parçayı ACK mekanizması ile gönderir
            if not send_with_ack(conn, header + chunk):
                print(f"[-] Paket {i} gönderilemedi")
                progress_bar.close()
                return False
            progress_bar.update(len(chunk))
        
        # Gönderimin bittiğini belirtmek için sıfır boyutlu bir başlık gönderir
        print("[*] Bitiş paketi gönderiliyor...")
        if not send_with_ack(conn, f"{0:<{HEADER_SIZE}}".encode()):
            print("[-] Bitiş paketi onayı alınamadı")
            progress_bar.close()
            return True
        progress_bar.close()
        print("[✓] Dosya gönderildi")
        return True
    except Exception as e:
        print(f"[-] Dosya gönderim hatası: {e}")
        return False

def receive_file(conn, outpath):
    """Şifreli dosyayı alır, çözer ve kaydeder."""
    data = b''
    packet_count = 0
    total_size = 0
    # İlerleme çubuğu ile alım sürecini görselleştirir
    progress_bar = tqdm(unit='B', unit_scale=True, desc="Alınıyor")
    try:
        while True:
            # Paket başlığını alır (boyut bilgisi)
            header = recv_with_ack(conn, HEADER_SIZE)
            if header is None or len(header) != HEADER_SIZE:
                print("[-] Header alınamadı")
                return False
            size = int(header.decode().strip())
            if size == 0:
                # Sıfır boyutlu başlık, gönderimin bittiğini gösterir
                break
            # Belirtilen boyutta veri parçasını alır
            chunk = recv_with_ack(conn, size)
            if chunk is None or len(chunk) != size:
                print(f"[-] Paket {packet_count+1} alınamadı")
                return False
            data += chunk
            total_size += size
            packet_count += 1
            print(f"[*] Paket {packet_count} alındı ({size} bayt)")
            progress_bar.update(size)
        progress_bar.close()
        
        # Verinin minimum uzunluğunu kontrol eder (SHA256: 32 bayt, nonce+tag: 32 bayt)
        if len(data) < 64:
            print(f"[-] Yetersiz veri: {len(data)} bayt")
            return False
        # Checksum ve şifreli veriyi ayırır
        checksum_received = data[:32]
        encrypted_data = data[32:]
        # Veriyi çözer
        decrypted = decrypt_data(encrypted_data)
        # Checksum ile veri bütünlüğünü kontrol eder
        if calculate_sha256(decrypted) != checksum_received:
            print("[-] Checksum uyuşmazlığı")
            return False
        # Çözülen veriyi dosyaya kaydeder
        with open(outpath, 'wb') as f:
            f.write(decrypted)
        print(f"[✓] Dosya alındı: {len(decrypted)} bayt")
        return True
    except Exception as e:
        print(f"[!] Alım hatası: {e}")
        progress_bar.close()
        return False

# --- RSA/AES Anahtar Değişimi ---

def rsa_key_exchange_server(conn):
    """Sunucu tarafında RSA ile AES anahtar değişimi yapar."""
    global AES_KEY
    # 2048 bitlik RSA anahtar çifti oluşturur
    rsa = RSA.generate(2048)
    private_key = rsa
    public_key = rsa.publickey()
    # Genel anahtarı (public key) PEM formatında istemciye gönderir
    pub_pem = public_key.export_key()
    conn.sendall(struct.pack('!I', len(pub_pem)))
    conn.sendall(pub_pem)
    # İstemciden şifrelenmiş AES anahtarını alır
    size = struct.unpack('!I', conn.recv(4))[0]
    enc_aes = conn.recv(size)
    # Özel anahtar ile AES anahtarını çözer
    cipher_rsa = PKCS1_OAEP.new(private_key)
    AES_KEY = cipher_rsa.decrypt(enc_aes)
    print("[✓] RSA ile AES anahtarı alındı.")

def rsa_key_exchange_client(conn):
    """İstemci tarafında RSA ile AES anahtar değişimi yapar."""
    global AES_KEY
    # Sunucudan genel anahtarı alır
    size = struct.unpack('!I', conn.recv(4))[0]
    pub_pem = conn.recv(size)
    public_key = RSA.import_key(pub_pem)
    # Rastgele 16 baytlık AES anahtarı oluşturur
    AES_KEY = get_random_bytes(16)
    # Genel anahtar ile AES anahtarını şifreler
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_aes = cipher_rsa.encrypt(AES_KEY)
    # Şifrelenmiş AES anahtarını sunucuya gönderir
    conn.sendall(struct.pack('!I', len(enc_aes)))
    conn.sendall(enc_aes)
    print("[✓] AES anahtarı sunucuya gönderildi.")

# --- Ağ Simülasyon ve Test Fonksiyonları ---

def start_iperf3_server(port=5201):
    """iperf3 sunucusunu başlatır."""
    try:
        # iperf3 sunucusunun zaten çalışıp çalışmadığını kontrol eder
        result = subprocess.run(['netstat', '-tuln'], capture_output=True, text=True)
        if ':5201' in result.stdout:
            print("[i] iperf3 sunucusu zaten çalışıyor.")
            return None
        # iperf3 sunucusunu belirtilen portta başlatır
        process = subprocess.Popen(['iperf3', '-s', '-p', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(1)
        if process.poll() is None:
            print(f"[+] iperf3 sunucusu başlatıldı: port {port}")
            return process
        print("[-] iperf3 sunucusu başlatılamadı.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[-] iperf3 başlatma hatası: {e}")
        return None

def stop_iperf3_server(server_process):
    """iperf3 sunucusunu durdurur."""
    if server_process:
        try:
            # iperf3 sürecini düzenli bir şekilde sonlandırır
            server_process.terminate()
            server_process.wait(timeout=5)
            print("[+] iperf3 sunucusu durduruldu.")
        except subprocess.TimeoutExpired:
            # Zaman aşımı durumunda süreci zorla durdurur
            server_process.kill()
            print("[!] iperf3 sunucusu zorla durduruldu.")

def simulate_network_conditions(interface='lo', delay_ms=100, loss_percent=5):
    """Linux'ta ağ koşullarını simüle eder (gecikme ve paket kaybı)."""
    # Yalnızca Linux sistemlerinde çalışır
    if platform.system() != 'Linux':
        print("[!] tc simülasyonu yalnızca Linux'ta desteklenir.")
        return
    try:
        # tc komutu ile belirtilen arayüze gecikme ve paket kaybı ekler
        command = ['sudo', 'tc', 'qdisc', 'replace', 'dev', interface, 'root', 'netem',
                   'delay', f'{delay_ms}ms', 'loss', f'{loss_percent}%']
        subprocess.run(command, check=True)
        print(f"[+] {interface}: {delay_ms}ms gecikme, %{loss_percent} kayıp eklendi.")
    except subprocess.CalledProcessError as e:
        print(f"[-] tc komutu başarısız: {e}")

def measure_rtt(server_ip, interface=None):
    """Hedef IP'ye RTT ölçümü yapar."""
    try:
        # ping komutunu çalıştırır, belirli bir arayüz kullanılabilir
        cmd = ['ping', '-c', '20', server_ip]
        if interface and interface != 'lo':
            cmd += ['-I', interface]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"\n📡 Ping Çıktısı ({server_ip}):\n{result.stdout}")
        # RTT değerini düzenli ifade ile çıkarır
        rtt_match = re.search(r'rtt min/avg/max/mdev = [\d\.]+/([\d\.]+)/[\d\.]+/[\d\.]+ ms', result.stdout)
        if rtt_match:
            rtt = float(rtt_match.group(1))
            print(f"✅ Ortalama RTT: {rtt} ms -> {'⚡ Hızlı' if rtt < 00 else '🔴 Yavaş'}")
            return rtt
        print("[!] RTT değeri bulunamadı.")
        return None
    except subprocess.CalledProcessError as e:
        print(f"[!] Ping hatası: {e}")
        return None

# === Farklı ağ arayüzlerinde performans karşılaştırması yapar ===
def compare_network_conditions():
    """
    Farklı ağ arayüzlerinde RTT ve bant genişliği ölçer.
    Simülasyon opsiyonel, iperf3 çıktısı esnek bir şekilde işlenir.
    """
    # Kullanıcıdan test için sunucu IP'sini alır
    server_ip = input("Test için sunucu IP adresi (örn: 192.168.1.105): ").strip()
    if not server_ip:
        print("[!] Geçerli bir IP adresi girin.")
        return

    # Yerel IP'leri kontrol eder
    local_ips = [addr['addr'] for iface in netifaces.interfaces() for addr in netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])]
    if server_ip in local_ips:
        print(f"[!] Uyarı: {server_ip} yerel bir IP. Harici bir IP önerilir.")
        if input("Yerel IP ile devam etmek istiyor musunuz? (e/h): ").lower() != 'e':
            print("[!] Test iptal edildi.")
            return

    # Simülasyon ayarlarını sorar
    simulate = input("Ağ simülasyonu (gecikme ve paket kaybı) uygulansın mı? (e/h): ").lower() == 'e'
    delay_ms = 0
    loss_percent = 0
    if simulate:
        delay_ms = int(input("Gecikme süresi (ms, örn: 10): ") or 10)
        loss_percent = float(input("Paket kaybı oranı (%, örn: 1): ") or 1)

    # Mevcut ağ arayüzlerini listeler
    print("\n💡 Mevcut ağ arayüzleri:")
    interfaces = netifaces.interfaces()
    for i, iface in enumerate(interfaces):
        print(f"{i}. {iface}")
    selected = input("Karşılaştırmak istediğiniz arayüz numaralarını virgülle girin (örn: 0,1): ")
    indices = [int(i.strip()) for i in selected.split(",") if i.strip().isdigit()]
    selected_interfaces = [interfaces[i] for i in indices if 0 <= i < len(interfaces)]
    if not selected_interfaces:
        print("[!] Geçerli arayüz seçilmedi.")
        return

    # Yerel IP için iperf3 sunucusunu başlatır
    server_process = None
    if server_ip in local_ips:
        server_process = start_iperf3_server()
        if not server_process:
            print("[!] iperf3 sunucusu başlatılamadı. Test yapılamaz.")
            return
    else:
        # Harici sunucunun çalıştığını kontrol eder
        try:
            subprocess.run(['iperf3', '-c', server_ip, '-t', '1', '--connect-timeout', '1000'],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            print(f"[+] {server_ip}:5201 üzerinde iperf3 sunucusu çalışıyor.")
        except subprocess.CalledProcessError as e:
            print(f"[!] {server_ip}:5201 üzerinde iperf3 sunucusu çalışmıyor: {e.stderr.strip()}")
            print("[!] Lütfen sunucu cihazında 'iperf3 -s -p 5201' komutunu çalıştırın.")
            return

    # Test sonuçlarını saklar
    results = {}
    for iface in selected_interfaces:
        print(f"\n[*] {iface} için test yapılıyor...")
        # Simülasyon uygular (istenirse)
        if simulate:
            print(f"[*] {iface}: {delay_ms}ms gecikme, %{loss_percent} kayıp uygulanıyor...")
            simulate_network_conditions(iface, delay_ms=delay_ms, loss_percent=loss_percent)
        
        # RTT ölçümü yapar
        rtt = measure_rtt(server_ip, interface=iface)
        results[iface] = {'rtt': rtt, 'bandwidth': None}

        # iperf3 testi yapar
        print(f"[*] iperf3 testi başlatılıyor: {server_ip}:5201")
        try:
            cmd = ['iperf3', '-c', server_ip, '-p', '5201', '-t', '20', '-P', '1', '-i', '1']
            if iface != 'lo':
                cmd += ['--bind-dev', iface]
            print(f"[DEBUG] Çalıştırılan komut: {' '.join(cmd)}")
            iperf_result = subprocess.run(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30
            )
            print(f"[DEBUG] iperf3 çıktısı:\n{iperf_result.stdout}")
            if iperf_result.returncode != 0:
                print(f"[!] iperf3 hatası ({iface}): {iperf_result.stderr.strip()}")
            else:
                # iperf3 çıktısından bant genişliğini çıkarır
                bandwidth_match = re.search(r'(\d+\.\d+)\s+(Mbits/sec|Gbits/sec)', iperf_result.stdout, re.MULTILINE)
                if bandwidth_match:
                    bandwidth = float(bandwidth_match.group(1))
                    unit = bandwidth_match.group(2)
                    if unit == 'Gbits/sec':
                        bandwidth *= 1000  # Gbps to Mbps
                    results[iface]['bandwidth'] = bandwidth
                    print(f"[+] iperf3 testi başarılı: {bandwidth:.2f} Mbits/sec")
                else:
                    print("[!] iperf3 çıktısında bant genişliği bulunamadı.")
        except subprocess.TimeoutExpired:
            print(f"[!] iperf3 testi zaman aşımına uğradı ({iface}).")
        except Exception as e:
            print(f"[!] iperf3 çalıştırılamadı ({iface}): {e}")

        # Simülasyonu temizler
        if simulate:
            subprocess.run(['sudo', 'tc', 'qdisc', 'del', 'dev', iface, 'root'], check=False)
            print(f"[*] {iface} için simülasyon kaldırıldı.")
        time.sleep(2)

    # iperf3 sunucusunu durdurur
    stop_iperf3_server(server_process)

    # Sonuçları yazdırır
    print("\n=== 📊 Ağ Koşulları Karşılaştırması ===")
    for iface, data in results.items():
        rtt_status = "⚡ Hızlı" if data['rtt'] and data['rtt'] < 50 else "🟡 Orta" if data['rtt'] and data['rtt'] < 150 else "🔴 Yavaş"
        print(f"{iface}: RTT={data['rtt'] if data['rtt'] else 'Yok'} ms ({rtt_status}), "
              f"Bant Genişliği={data['bandwidth'] if data['bandwidth'] else 'Yok'} Mbits/sec")

# --- MITM ve Paket Manipülasyonu ---

def send_tcp_packet():
    """Manuel TCP paketi gönderir."""
    # Kullanıcıdan kaynak ve hedef IP'leri alır
    src_ip = input("Gönderen IP: ").strip()
    dst_ip = input("Hedef IP: ").strip()
    # Sabit kaynak ve hedef portlar ile test payload'u oluşturur
    src_port, dst_port, payload = 21573, 21332, b"TEST_IP_PACKET"
    # Scapy ile IP ve TCP katmanlarını içeren bir paket oluşturur
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=1000) / Raw(load=payload)
    # Paketi gönderir
    send(pkt, verbose=True)
    print("[✓] TCP paketi gönderildi.")

def packet_handler(pkt):
    """Yakalanan TCP paketlerini işler ve isteğe bağlı olarak içeriğini değiştirir."""
    global sent_flag
    # Yakalanan paketin özetini yazdırır
    print("[GELEN PAKET]:", pkt.summary())
    if pkt.haslayer(Raw):
        print("Payload:", pkt[Raw].load)
    if not sent_flag:
        # Kullanıcıya paketi değiştirme seçeneği sunar
        cevap = input("Paket içeriğini değiştirmek ister misiniz? (E/H): ").strip().upper()
        if cevap == 'E':
            # Yeni payload'u alır ve yeni bir paket oluşturur
            yeni_icerik = input("Ne yazmak istersiniz?: ").encode()
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags='PA', seq=pkt[TCP].seq + 1, ack=pkt[TCP].ack) / Raw(load=yeni_icerik)
                send(new_pkt, verbose=True)
                print(f"[✓] '{yeni_icerik.decode(errors='ignore')}' paketi gönderildi.")
            else:
                print("[!] Paket IP/TCP katmanına sahip değil.")
            sent_flag = True
        else:
            print("[i] Paket içeriği değiştirilmedi.")
            sent_flag = True

def mitm():
    """MITM simülasyonu ile TCP paketlerini dinler."""
    # Kullanıcıdan dinlenecek arayüz ve hedef IP'yi alır
    interface = input("Ağ arayüzü (örn: enp0s3): ").strip()
    target_ip = input("Dinlenecek IP (örn: 192.168.1.105): ").strip()
    print(f"[*] {target_ip} adresine gelen TCP paketleri dinleniyor...")
    # Scapy ile TCP paketlerini dinler ve her paket için packet_handler'ı çağırır
    sniff(filter=f"tcp and host {target_ip}", iface=interface, prn=packet_handler, store=0)

# --- Sunucu ve İstemci Fonksiyonları ---

def server(host='0.0.0.0', port=DEFAULT_PORT):
    """Sunucu modunda istemci bağlantılarını kabul eder ve dosya alır."""
    # TCP soketi oluşturur
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Soket seçeneklerini ayarlar (port yeniden kullanım ve keep-alive)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if platform.system() == "Windows":
        # Windows için keep-alive ayarları
        s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 500, 250))
    else:
        # Linux için keep-alive ayarları
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', 4), 1)
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', 5), 5)
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', 6), 3)
    try:
        # Sunucuyu belirtilen host ve porta bağlar
        s.bind((host, port))
        s.listen(1)
        print(f"[+] Sunucu dinlemede: {host}:{port}...")
        # İstemci bağlantısını kabul eder
        conn, addr = s.accept()
        print(f"[+] Bağlantı: {addr}")
        try:
            # Kimlik doğrulama bilgilerini alır ve kontrol eder
            creds = conn.recv(1024).decode().split(',')
            if len(creds) != 2 or creds[0] != VALID_USERNAME or creds[1] != hashlib.sha256(VALID_PASSWORD.encode()).hexdigest():
                conn.sendall(b'AUTH_FAILED\n')
                print("[-] Kimlik doğrulama başarısız.")
                return
            conn.sendall(b'AUTH_SUCCESS\n')
            print("[+] Kimlik doğrulama başarılı.")
            # Bağlantı kontrolü yapar
            check = conn.recv(5)
            if check != b'CHECK':
                print(f"[-] Bağlantı kontrolü başarısız: {check}")
                return
            conn.sendall(b'CHECK')
            print("[+] Bağlantı kontrolü başarılı.")
            # RSA ile AES anahtar değişimi yapar
            rsa_key_exchange_server(conn)
            # Dosyayı alır
            if receive_file(conn, 'received_output.txt'):
                print("[+] Dosya alındı.")
            else:
                print("[-] Dosya alımı başarısız.")
        except socket.timeout:
            print("[!] Zaman aşımı.")
        except Exception as e:
            print(f"[!] Sunucu hatası: {e}")
        finally:
            conn.close()
    except KeyboardInterrupt:
        print("[!] Sunucu kapatılıyor...")
    finally:
        s.close()

def client(server_ip='127.0.0.1', port=DEFAULT_PORT):
    """İstemci modunda sunucuya bağlanır ve dosya gönderir."""
    # TCP soketi oluşturur
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Soket seçeneklerini ayarlar (keep-alive)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if platform.system() == "Windows":
        s.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 500, 250))
    else:
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPIDLE', 4), 1)
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPINTVL', 5), 5)
        s.setsockopt(socket.IPPROTO_TCP, getattr(socket, 'TCP_KEEPCNT', 6), 3)
    try:
        # Sunucuya bağlanır
        print(f"[*] Sunucuya bağlanılıyor: {server_ip}:{port}")
        s.connect((server_ip, port))
        print("[+] Bağlantı başarılı.")
        # Kullanıcıdan kimlik doğrulama bilgilerini alır
        user = input("Kullanıcı adı: ")
        pwd = input("Şifre: ")
        pwd_hash = hashlib.sha256(pwd.encode()).hexdigest()
        s.sendall(f"{user},{pwd_hash}".encode())
        # Kimlik doğrulama yanıtını kontrol eder
        s.settimeout(60)
        res = s.recv(1024).decode()
        if res.split('\n')[0] != 'AUTH_SUCCESS':
            print(f"[-] Kimlik doğrulama başarısız: {res}")
            return
        print("[+] Kimlik doğrulama başarılı.")
        # Bağlantı kontrolü yapar
        s.sendall(b'CHECK')
        if s.recv(5) != b'CHECK':
            print("[-] Bağlantı kontrolü başarısız.")
            return
        print("[+] Bağlantı kontrolü başarılı.")
        # RSA ile AES anahtar değişimi yapar
        rsa_key_exchange_client(s)
        # Dosya yolunu alır ve gönderir
        filepath = input("Gönderilecek dosya yolu: ").strip()
        if not os.path.isfile(filepath):
            print("[-] Dosya mevcut değil.")
            return
        if send_file(s, filepath):
            print("[+] Dosya gönderildi.")
        else:
            print("[-] Dosya gönderimi başarısız.")
    except socket.timeout:
        print("[!] Zaman aşımı.")
    except KeyboardInterrupt:
        print("[!] Kullanıcı tarafından kesildi.")
    except Exception as e:
        print(f"[!] İstemci hatası: {e}")
    finally:
        s.close()

# --- Ana Program Akışı ---

if __name__ == '__main__':
    """Kullanıcı mod seçimi ile programı çalıştırır."""
    print("=== Güvenli Dosya Transfer Sistemi ===")
    # Kullanıcıdan çalıştırılacak modu alır
    mode = input("Mod seçin: Sunucu (s), İstemci (c), Manuel IP Test (t), Ağ Karşılaştırması (a), MITM Paket Gönderimi (p), MITM Simülasyonu (m): ").lower()
    sent_flag = False
    if mode == "s":
        # Sunucu modunu başlatır
        server()
    elif mode == "c":
        # İstemci modunu başlatır, sunucu IP'sini alır
        ip = input("Sunucu IP adresi: ").strip()
        client(server_ip=ip)
    elif mode == "t":
        # Manuel IP paketi gönderme modunu başlatır (Linux-only)
        if platform.system() != 'Linux':
            print("[!] Bu özellik yalnızca Linux'ta çalışır.")
        else:
            src_ip = input("İstemci IP adresi: ").strip()
            target_ip = input("Hedef IP adresi: ").strip()
            payload = b'MANUAL_TEST_IP_PACKET'
            try:
                # Özel IP başlığı oluşturur ve paketi gönderir
                ip_header = create_ip_header(source_ip=src_ip, dest_ip=target_ip, payload_len=len(payload))
                packet = ip_header + payload
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                sock.sendto(packet, (target_ip, 0))
                sock.close()
                print("[✓] IP paketi gönderildi.")
            except PermissionError:
                print("[-] Root yetkisi gerekir.")
            except Exception as e:
                print(f"[-] IP paketi gönderim hatası: {e}")
    elif mode == "a":
        # Ağ performansı karşılaştırma modunu başlatır
        compare_network_conditions()
    elif mode == "p":
        # TCP paketi gönderme modunu başlatır
        send_tcp_packet()
    elif mode == "m":
        # MITM simülasyon modunu başlatır
        mitm()
    else:
        print("[-] Geçersiz mod.")