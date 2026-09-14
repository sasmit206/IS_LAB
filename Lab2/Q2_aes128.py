from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

key = b"0123456789ABCDEF0123456789ABCDEF"
message = b"Sensitive Information"

#encrypt
cipher = AES.new(key,AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message,16))

print("Ciphertext: ", ciphertext.hex())

#decrypt:

cipher = AES.new(key,AES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext),16)

print("Decrypted: ", plaintext.decode())