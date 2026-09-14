# 1. Encrypt the message "I am learning information security" using one of the following ciphers.
# Ignore the space between words. Decrypt the message to get the original plaintext:
# a) Additive cipher with key = 20
# b) Multiplicative cipher with key = 15
# c) Affine cipher with key = (15, 20)

from math import gcd

#helper functions:
def inverse(k):
    for i in range(0,26):
        if (k*i) % 26 == 1:
            return i
    return -1

def additive_cipher_encryption(plaintext,k):
    ciphertext = ""
    for ch in plaintext:
        p = ord(ch) - ord('a')
        c = (p + k) % 26
        ciphertext += chr(c+ord('a'))
    return ciphertext

def additive_cipher_decryption(ciphertext,k):
    plaintext = ""
    for ch in ciphertext:
        c = ord(ch) - ord('a')
        p = (c - k) % 26
        plaintext += chr(p+ord('a'))
    return plaintext

def multiplicative_cipher_encryption(plaintext, k):
    if gcd(k,26) != 1:
        return "GCD of key and size of character space should be 1!!!"
    ciphertext = ""
    for ch in plaintext:
        p = ord(ch) - ord('a')
        c = (p * k) % 26
        ciphertext += chr(c + ord('a'))
    return ciphertext

def multiplicative_cipher_decryption(ciphertext, k):
    if gcd(k, 26) != 1:
        return "GCD of key and size of character space should be 1!!!"
    plaintext = ""
    kinv = inverse(k)

    for ch in ciphertext:
        c = ord(ch) - ord('a')
        p = (c * kinv) % 26
        plaintext += chr(p + ord('a'))
    return plaintext

def affine_cipher_encryption(plaintext, k1, k2):
    if gcd(k1,26) != 1:
        return "GCD of key and size of character space should be 1!!!"
    ciphertext = ""
    for ch in plaintext:
        p = ord(ch) - ord('a')
        c = ((p * k1) + k2) % 26
        ciphertext += chr(c + ord('a'))
    return ciphertext

def affine_cipher_decyption(ciphertext, k1, k2):
    if gcd(k1,26) != 1:
        return "GCD of key and size of character space should be 1!!!"
    plaintext = ""
    k1inv = inverse(k1)
    for ch in ciphertext:
        c = ord(ch) - ord('a')
        p = (((c - k2)) * k1inv) % 26
        plaintext += chr(p + ord('a'))
    return plaintext

def main():
    while True:
        print("\n--- Cipher Menu ---")
        print("1. Additive Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Exit")

        choice = input("Enter your choice (1-4): ")

        if choice == "4":
            print("Program ended.")
            break

        if choice not in ("1", "2", "3"):
            print("Invalid choice. Please try again.")
            continue

        print("\n1. Encryption")
        print("2. Decryption")
        operation = input("Enter operation (1-2): ")

        if operation not in ("1", "2"):
            print("Invalid operation.")
            continue

        text = input("Enter text: ").lower().replace(" ", "")

        if choice == "1":
            k = int(input("Enter additive key: "))

            if operation == "1":
                print("Ciphertext:", additive_cipher_encryption(text, k))
            else:
                print("Plaintext:", additive_cipher_decryption(text, k))

        elif choice == "2":
            k = int(input("Enter multiplicative key: "))

            if operation == "1":
                print("Ciphertext:", multiplicative_cipher_encryption(text, k))
            else:
                print("Plaintext:", multiplicative_cipher_decryption(text, k))

        elif choice == "3":
            k1 = int(input("Enter multiplicative key (k1): "))
            k2 = int(input("Enter additive key (k2): "))

            if operation == "1":
                print("Ciphertext:", affine_cipher_encryption(text, k1, k2))
            else:
                print("Plaintext:", affine_cipher_decyption(text, k1, k2))


main()
