from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad

key = b"A1B2C3D4"
message = b"Confidential Data"

#Encryption:

cipher = DES.new(key, DES.MODE_ECB)
ciphertext = cipher.encrypt(pad(message,8))

print("Ciphertext: ",ciphertext.hex())

cipher = DES.new(key, DES.MODE_ECB)
plaintext = unpad(cipher.decrypt(ciphertext),8)


print("Decrypted: ", plaintext.decode())