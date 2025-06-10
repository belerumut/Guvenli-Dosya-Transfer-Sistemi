import hashlib

# Sunucuda kaydedilen dosyayı oku
with open("received_output.txt", "rb") as f:
    data = f.read()

# SHA-256 hesapla
h = hashlib.sha256(data).hexdigest()

print("Python hash: ", h)
print("Wireshark hash: ", "WS_HASH")
