from math import gcd


def RSA(plaintext):
    p = 10007
    q = 10009

    n = p * q
    phi = (p - 1)*(q - 1)


    e = -1

    for i in range(2,phi):
        if gcd(i,phi) == 1:
            e = i
            break

    d = -1
    for i in range (1, phi):
        if (e * i) % phi == 1:
            d = i
            break

    print("n =", n)
    print("phi =", phi)
    print("e =", e)
    print("d =", d)

    ciphertext = []

    for ch in plaintext:
        M = ord(ch) - ord('a')
        C = pow(M,e,n)
        ciphertext.append(C)

    return ciphertext


def main():
    plaintext = "Asymmetric Encryption"
    plaintext = plaintext.lower().replace(" ","")
    print(RSA(plaintext))

main()