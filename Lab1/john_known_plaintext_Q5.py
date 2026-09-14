# John is reading a mystery book involving cryptography. In one part of the book, the author
# gives a ciphertext "CIW" and two paragraphs later the author tells the reader that this is a shift
# cipher and the plaintext is "yes". In the next chapter, the hero found a tablet in a cave with
# "XVIEWYWI" engraved on it. John immediately found the actual meaning of the ciphertext.
# Identify the type of attack and plaintext

def findShift(ciphertext, plaintext):
    ciphertext = ciphertext.upper()
    plaintext = plaintext.upper()
    if(len(ciphertext) != len(plaintext)):
        return None

    diff = []
    for c, p in zip(ciphertext, plaintext):
        diff.append((ord(c) - ord(p)) % 26)

    if(len(set(diff)) != 1):
        return None
    return diff[0]

def decrypt(ciphertext, key):
    ciphertext = ciphertext.upper()
    plaintext = ""
    for ch in ciphertext:
        c = ord(ch) - ord('A')
        p = ( c - key ) % 26
        plaintext += chr(p + ord('A'))
    return plaintext


def main():
    cipher = "CIW"
    plain = "YES"

    key = findShift(cipher, plain)

    if key is not None:
        print("Shift =", key)
        print("Attack = Known Plaintext Attack")
        print("Plaintext =", decrypt("XVIEWYWI", key))
    else:
        print("Invalid plaintext-ciphertext pair.")

main()
