import time

from Crypto.Cipher import AES,DES
from Crypto.Util.Padding import pad,unpad

N = 10000

message = b"Performance Testing of Encryption Algorithms"

des_key = b"12345678"
aes_key = b"12345678901234567890123456789012"

# ------------------- DES -------------------

start = time.perf_counter()

for _ in range(N):
    des = DES.new(des_key,DES.MODE_ECB)
    des_ciphertext = des.encrypt(pad(message,8))

des_encrypt_time = time.perf_counter() - start


start = time.perf_counter()

for _ in range(N):
    des = DES.new(des_key,DES.MODE_ECB)
    des_plaintext = unpad(des.decrypt(des_ciphertext),8)

des_decrypt_time = time.perf_counter() - start


# ------------------- AES -------------------

start = time.perf_counter()

for _ in range(N):
    aes = AES.new(aes_key,AES.MODE_ECB)
    aes_ciphertext = aes.encrypt(pad(message,16))

aes_encrypt_time = time.perf_counter() - start


start = time.perf_counter()

for _ in range(N):
    aes = AES.new(aes_key,AES.MODE_ECB)
    aes_plaintext = unpad(aes.decrypt(aes_ciphertext),16)

aes_decrypt_time = time.perf_counter() - start


# ---------------- Results ----------------

print("DES Encryption Time :", des_encrypt_time)
print("DES Decryption Time :", des_decrypt_time)

print("AES-256 Encryption Time :", aes_encrypt_time)
print("AES-256 Decryption Time :", aes_decrypt_time)

print("\nDES Decrypted :", des_plaintext.decode())
print("AES Decrypted :", aes_plaintext.decode())