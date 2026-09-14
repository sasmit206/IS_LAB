def findInv(key):
    for i in range(26):
        if (i * key) % 26 == 1:
            return i;
    return -1

def affine_encrypt(plaintext, k1, k2):
    plaintext = plaintext.upper()
    cipher = ""
    for ch in plaintext:
        p = ord(ch) - ord('A')
        c = ( p * k1 + k2 ) % 26
        cipher += chr(c + ord('A'))
    return cipher

def affine_decrypt(ciphertext, k1, k2):
    inv = findInv(k1)
    ciphertext = ciphertext.upper()
    plaintext = ""
    for ch in ciphertext:
        c = ord(ch) - ord('A')
        p = ( (c - k2) * inv ) % 26
        plaintext += chr(p + ord('A'))
    return plaintext

def bruteForce(ciphertext):
    target = "GL"

    for k1 in range(26):

        if(findInv(k1) == -1):
            continue

        for k2 in range(26):

            if(affine_encrypt("AB", k1, k2) == target):
                print("Key found")
                print("K1 =" , k1)
                print("K2 =" , k2)

                plain = affine_decrypt(ciphertext, k1, k2)

                print("Plaintext =", plain)
                return

    print("Key not found")

def main():
    ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
    bruteForce(ciphertext)


main()
