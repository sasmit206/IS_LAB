import random

# # Publicly known:
#     p, g
#
# # Key generation:
#     Private key = x
#     Public key component = h = g^x mod p
#
# # Therefore:
#     Public key  = (p, g, h)
#     Private key = x
#
# # Encryption:
#     1. Choose a random value k
#     2. Calculate c1 = g^k mod p
#     3. Calculate c2 = m × h^k mod p
#     4. Ciphertext = (c1, c2)
#
# # Decryption:
#     5. Calculate s = c1^x mod p
#     6. Calculate s^(-1) mod p
#     7. Calculate m = c2 × s^(-1) mod p
#     8. Convert m back to the original character/message
#
# # Result:
#     Decrypted message = Original message

#elgamal encryption:

def encrypt(message,p,g,h):
    ciphertext = []

    for ch in message:
        if ch == " ":
            ciphertext.append(" ")
            continue
        m = ord(ch) - ord('A')

        #random k:
        k = random.randint(1,p-2)

        #c1 = g^k mod p
        c1 = pow(g,k,p)

        #c2 = m * h^k mod p
        c2 = (m * pow(h,k,p)) % p

        ciphertext.append((c1,c2))

    return ciphertext


def decrypt(ciphertext,p,x):
    plaintext = ""

    for item in ciphertext:

        if item == " ":
            plaintext += " "
            continue

        c1, c2 = item

        #s = c1^x mod p
        s = pow(c1,x,p)

        #s^(-1) mod p
        s_inv = pow(s,-1,p)

        #m = c2 * s^(-1) mod p

        m = (c2*s_inv)%p

        plaintext += chr(m+ord('A'))

    return plaintext

def main():

    plaintext = "Confidential Data"

    p = 467
    g = 2

    #private key
    x = 127

    h = pow(g,x,p)

    print("p =",p)
    print("g = ",g)
    print("h =",h)

    print("Public key = ",(p,g,h))
    print("Private key = ",x)

    #encryption:
    ciphertext = encrypt(plaintext,p,g,h)

    print("\nPlaintext: ",plaintext)
    print("\nCiphertext: ",ciphertext)

    #decryption:
    decrypted = decrypt(ciphertext,p,x)

    print("\nDecrypted: ",decrypted)

    print("\nVerification: ", decrypted == plaintext)

main()