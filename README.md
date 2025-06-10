# 🔐 Güvenli Dosya Transfer Sistemi

Bu Python projesi, istemci-sunucu mimarisiyle güvenli bir dosya transfer sistemi sunar. AES ve RSA şifreleme algoritmaları ile güvenli iletişim sağlarken, aynı zamanda ağ performansı ölçümü (RTT, bant genişliği), manuel TCP/IP paket gönderimi ve MITM simülasyonu gibi ileri düzey ağ işlevleri de sunar.

## 📌 Özellikler

- ✅ RSA + AES hibrit şifreleme ile anahtar paylaşımı ve veri güvenliği
- ✅ SHA-256 özet fonksiyonu ile veri bütünlüğü kontrolü
- 📁 Dosya gönderimi (şifreli, parçalı ve onaylı - ACK destekli)
- 🔐 Kimlik doğrulama (sabit kullanıcı adı ve SHA-256 hash ile)
- 📡 RTT ölçümü ve bağlantı kontrolü
- 📶 iPerf3 ile bant genişliği testi
- ⚙️ Ağ gecikmesi ve paket kaybı simülasyonu (Linux'ta `tc` komutu ile)
- 🌐 Farklı ağ arayüzlerinde performans karşılaştırması
- 🛠️ Manuel IP paketi oluşturma ve gönderme
- 🕵️ MITM simülasyonu: Paket dinleme ve değiştirme (Scapy ile)

---

## 📦 Gereksinimler

### 🐍 Python Sürümü

- Python 3.8 veya üzeri

### 📚 Kütüphaneler

Gerekli kütüphaneler:
```bash
pip install pycryptodome scapy tqdm netifaces
```

### 🛠️ Harici Araçlar

- iperf3: Ağ bant genişliği testi için
- tc: Ağ simülasyonu için (sadece Linux, sudo yetkisi gerekir)

## 🚀 Kullanım Senaryosu

Bütün visual studio code kullanarak çalıştırabilirsiniz.

+ Dosya_guvenlik_sistemi.py dosyasını terminalden çalıştırarak bir mod seçimi yapın:

### 🧭 Modlar ve Açıklamaları

| Kısaltma | Mod Adı                  | Açıklama                                                                 |
|----------|--------------------------|--------------------------------------------------------------------------|
| `s`      | Sunucu Modu              | Dosya alır, kimlik doğrulama ve özet kontrolü yapar                     |
| `c`      | İstemci Modu             | Dosya gönderir, bağlantı testi ve kimlik doğrulama yapar                |
| `t`      | Manuel IP Testi          | Manuel IP paketi gönderimi yapar _(yalnızca Linux)_                     |
| `a`      | Ağ Karşılaştırması       | Farklı ağ arayüzlerinde RTT ve bant genişliği karşılaştırması yapar    |
| `p`      | TCP Paketi Gönderimi     | Manuel TCP paketi oluşturup gönderir                                    |
| `m`      | MITM Simülasyonu         | TCP paketlerini dinler, içeriğini görüntüler veya değiştirir            |


### 🧪 Örnek Senaryolar

+ 🔒 1. Sunucu Başlatma
```bash
python Dosya_guvenlik_sistemi.py

# Mod seçin: s
```

+ 🚚 2. İstemci ile Dosya Gönderme
```bash
python Dosya_guvenlik_sistemi.py
# Mod seçin: c
# Sunucu IP adresi: 192.168.1.100
# Kullanıcı adı: username
# Şifre: password
# Gönderilecek dosya yolu: C:\Users\burak\Desktop\dosya.txt
```
- İstemci tarafından gönderilen dosya içeriği kod dosyaları içerisinde bulunan "received_output.txt" isimli dosya içerine kaydedilir.


📶 3. Ağ Performansını Test Etme
```bash
python Dosya_guvenlik_sistemi.py
# Mod seçin: a
# Sunucu IP adresi: 192.168.1.105
# Ağ arayüzü giriniz: enp0s3
# tc komutu ile gecikme ve kayıp simülasyonu isteğe göre uygulanır
```
- RTT ve iPerf3 bant genişliği ölçümü yapılır


### 🧪 Gelişmiş Test Modları

#### 🌐 Manuel IP Paketi Gönderimi (Linux)

- IP başlığı özel olarak oluşturulur (create_ip_header)
- Ham soket kullanılarak gönderilir

#### 🕵️ MITM Simülasyonu

- scapy ile belirli bir IP adresine gelen TCP paketleri dinlenir
- Kullanıcı isterse paketi değiştirip geri gönderir
⚠️ MITM modunun etik dışı veya izinsiz kullanımına karşı dikkatli olun. Bu araç yalnızca eğitim ve test amaçlıdır.⚠️


## ▶️ Projenin Tanıtımı Videosu

+ Aşağıdaki linkten projenin tanıtım videosunu izleyebilirsiniz.

    🎥 Video linki: https://www.youtube.com/watch?v=C6XzuEqmTqU
