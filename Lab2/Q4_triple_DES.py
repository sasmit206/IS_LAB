from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad,unpad

key = b"1234567890ABCDEF12345678"
message = b"Classified Text"

#encrypt
des3 = DES3.new(key, DES3.MODE_ECB)
ciphertext = des3.encrypt(pad(message,8))

print("Ciphertext: ", ciphertext.hex())

#decrypt
des3 = DES3.new(key, DES3.MODE_ECB)
plaintext = unpad(des3.decrypt(ciphertext),8)

print("Decrypted: ",plaintext.decode())