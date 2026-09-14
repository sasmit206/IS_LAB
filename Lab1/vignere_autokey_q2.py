# 2. Encrypt the message "the house is being sold tonight" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# • Vigenere cipher with key: "dollars"
# • Autokey cipher with key = 7


# C = (P + K) mod 26
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.lower().replace(' ', '')
    key = key.lower().replace(' ', '')
    ciphertext = ''
    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - ord('a')
        k = ord(key[i%len(key)]) - ord('a')
        c = (p + k) % 26
        ciphertext += chr(c + ord('a'))

    return ciphertext


# P = (C - K) mod 26
def vigenere_decrypt(ciphertext, key):
    ciphertext = ciphertext.lower().replace(' ', '')
    key = key.lower().replace(' ', '')
    plaintext = ''
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('a')
        k = ord(key[i % len(key)]) - ord('a')
        p = (c - k) % 26
        plaintext += chr(p + ord('a'))

    return plaintext

# C = (P + K) mod 26
def autokey_encrypt(plaintext, key):
    plaintext = plaintext.lower().replace(' ', '')
    ciphertext = ''
    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - ord('a')
        if i == 0:
            k = key
        else:
            k = ord(plaintext[i-1]) - ord('a')
        c = (p + k) % 26
        ciphertext += chr(c + ord('a'))
    return ciphertext

# P = (C - K) mod 26
def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.lower().replace(' ', '')
    plaintext = ''
    for i in range(len(ciphertext)):
        c = ord(ciphertext[i]) - ord('a')

        if i == 0:
            k = key
        else:
            k = ord(plaintext[i-1]) - ord('a')
        p = (c - k) % 26
        plaintext += chr(p + ord('a'))
    return plaintext



def main():
    while True:
        print("\n===== Polyalphabetic Cipher Menu =====")
        print("1. Vigenere Cipher")
        print("2. Autokey Cipher")
        print("3. Exit")

        choice = int(input("Enter your choice: "))

        if choice == 1:
            plaintext = input("Enter plaintext: ")
            key = input("Enter key: ")

            ciphertext = vigenere_encrypt(plaintext, key)

            print("Ciphertext :", ciphertext)

            decrypted = vigenere_decrypt(ciphertext, key)

            print("Plaintext  :", decrypted)

        elif choice == 2:
            plaintext = input("Enter plaintext: ")
            key = int(input("Enter initial key: "))

            ciphertext = autokey_encrypt(plaintext, key)

            print("Ciphertext :", ciphertext)

            decrypted = autokey_decrypt(ciphertext, key)

            print("Plaintext  :", decrypted)

        elif choice == 3:
            print("Exiting...")
            break

        else:
            print("Invalid choice!")

main()
