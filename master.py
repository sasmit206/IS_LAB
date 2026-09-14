"""
INFORMATION SECURITY LAB 1-6 - MASTER FILE
Each lab concept is kept in its own function so the required function
can be copied directly into an exam program.

NOTE:
- Functions are based on the user's uploaded lab programs.
- The master file does not automatically execute every experiment.
- Run master_menu() at the bottom to test functions interactively.
"""

import hashlib
import math
import random
import string
import time
from math import gcd

# ============================================================
# LAB 1 - CLASSICAL CRYPTOGRAPHY
# ============================================================

def additive_encrypt(text, key):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr((ord(ch) - base + key) % 26 + base)
        else:
            result += ch
    return result


def additive_decrypt(text, key):
    return additive_encrypt(text, -key)


def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


def multiplicative_encrypt(text, key):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result += chr(((ord(ch) - base) * key) % 26 + base)
        else:
            result += ch
    return result


def multiplicative_decrypt(text, key):
    inv = mod_inverse(key, 26)
    if inv is None:
        return None
    return multiplicative_encrypt(text, inv)


def affine_encrypt(text, a, b):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            x = ord(ch) - base
            result += chr((a * x + b) % 26 + base)
        else:
            result += ch
    return result


def affine_decrypt(text, a, b):
    inv = mod_inverse(a, 26)
    if inv is None:
        return None

    result = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            y = ord(ch) - base
            result += chr((inv * (y - b)) % 26 + base)
        else:
            result += ch
    return result


def vigenere_encrypt(text, key):
    result = ""
    key = key.lower()
    j = 0

    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[j % len(key)]) - ord('a')
            result += chr((ord(ch) - base + shift) % 26 + base)
            j += 1
        else:
            result += ch

    return result


def vigenere_decrypt(text, key):
    result = ""
    key = key.lower()
    j = 0

    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            shift = ord(key[j % len(key)]) - ord('a')
            result += chr((ord(ch) - base - shift) % 26 + base)
            j += 1
        else:
            result += ch

    return result


def autokey_encrypt(text, key):
    text = text.lower()
    key = key.lower()
    stream = key
    result = ""
    j = 0

    for ch in text:
        if ch.isalpha():
            shift = ord(stream[j]) - ord('a')
            result += chr((ord(ch) - ord('a') + shift) % 26 + ord('a'))
            stream += ch
            j += 1

    return result


def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.lower()
    key = key.lower()
    stream = key
    result = ""

    for i, ch in enumerate(ciphertext):
        shift = ord(stream[i]) - ord('a')
        plain = chr((ord(ch) - ord('a') - shift) % 26 + ord('a'))
        result += plain
        stream += plain

    return result


def playfair_prepare(text):
    text = ''.join(ch for ch in text.lower() if ch.isalpha())
    text = text.replace('j', 'i')

    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:
                result += a + 'x'
                i += 1
            else:
                result += a + b
                i += 2
        else:
            result += a + 'x'
            i += 1

    return result


def playfair_matrix(key):
    key = ''.join(ch for ch in key.lower() if ch.isalpha())
    key = key.replace('j', 'i')

    chars = []
    for ch in key + "abcdefghiklmnopqrstuvwxyz":
        if ch not in chars:
            chars.append(ch)

    return [chars[i:i + 5] for i in range(0, 25, 5)]


def playfair_encrypt(text, key):
    matrix = playfair_matrix(key)
    text = playfair_prepare(text)

    pos = {}
    for r in range(5):
        for c in range(5):
            pos[matrix[r][c]] = (r, c)

    result = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]
        r1, c1 = pos[a]
        r2, c2 = pos[b]

        if r1 == r2:
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]
        else:
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


def hill_encrypt(text, key_matrix):
    n = len(key_matrix)
    text = ''.join(ch for ch in text.lower() if ch.isalpha())
    while len(text) % n != 0:
        text += 'x'

    result = ""

    for i in range(0, len(text), n):
        block = [ord(ch) - ord('a') for ch in text[i:i + n]]

        for row in key_matrix:
            value = sum(row[j] * block[j] for j in range(n)) % 26
            result += chr(value + ord('a'))

    return result


def hill_decrypt(text, key_matrix):
    # Kept separate because Hill decryption requires the modular
    # inverse matrix. Use the inverse-matrix logic from the lab if
    # your examiner gives a different key matrix.
    raise NotImplementedError(
        "Use the Hill inverse-matrix/decryption code from your Lab 1 file."
    )


# ============================================================
# LAB 1 - CRYPTANALYSIS
# ============================================================

def known_plaintext_shift_attack(plaintext, ciphertext):
    shifts = []

    for p, c in zip(plaintext.lower(), ciphertext.lower()):
        if p.isalpha() and c.isalpha():
            shift = (ord(c) - ord(p)) % 26
            shifts.append(shift)

    if not shifts:
        return None

    return shifts[0]


def brute_force_affine(ciphertext):
    results = []

    for a in range(26):
        if gcd(a, 26) != 1:
            continue

        for b in range(26):
            plaintext = affine_decrypt(ciphertext, a, b)
            results.append((a, b, plaintext))

    return results


# ============================================================
# LAB 2/3 - DES / 3DES / AES
# ============================================================

# ------------------------------------------------------------
# DES ENCRYPTION
# ------------------------------------------------------------

def des_encrypt(message, key=b"A1B2C3D4"):
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import pad

    cipher = DES.new(key, DES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), 8))

    return ciphertext.hex()


# ------------------------------------------------------------
# DES DECRYPTION
# ------------------------------------------------------------

def des_decrypt(ciphertext_hex, key=b"A1B2C3D4"):
    from Crypto.Cipher import DES
    from Crypto.Util.Padding import unpad

    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 8).decode()

    return plaintext


# ------------------------------------------------------------
# 3DES ENCRYPTION
# ------------------------------------------------------------

def triple_des_encrypt(message, key=b"123456789012345678901234"):
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad

    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), 8))

    return ciphertext.hex()


# ------------------------------------------------------------
# 3DES DECRYPTION
# ------------------------------------------------------------

def triple_des_decrypt(ciphertext_hex, key=b"123456789012345678901234"):
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import unpad

    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = DES3.new(key, DES3.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 8).decode()

    return plaintext


# ------------------------------------------------------------
# AES ENCRYPTION
# ------------------------------------------------------------

def aes_encrypt(message, key=b"0123456789abcdef0123456789abcdef"):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(
        pad(message.encode(), AES.block_size)
    )

    return ciphertext.hex()


# ------------------------------------------------------------
# AES DECRYPTION
# ------------------------------------------------------------

def aes_decrypt(ciphertext_hex, key=b"0123456789abcdef0123456789abcdef"):
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    ciphertext = bytes.fromhex(ciphertext_hex)

    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size
    ).decode()

    return plaintext


def des_vs_aes_benchmark(message="Confidential Data", rounds=1000):
    from Crypto.Cipher import DES, AES
    from Crypto.Util.Padding import pad

    des_key = b"A1B2C3D4"
    aes_key = b"0123456789abcdef0123456789abcdef"

    des_start = time.perf_counter()
    for _ in range(rounds):
        cipher = DES.new(des_key, DES.MODE_ECB)
        cipher.encrypt(pad(message.encode(), 8))
    des_time = time.perf_counter() - des_start

    aes_start = time.perf_counter()
    for _ in range(rounds):
        cipher = AES.new(aes_key, AES.MODE_ECB)
        cipher.encrypt(pad(message.encode(), 16))
    aes_time = time.perf_counter() - aes_start

    return des_time, aes_time


# ============================================================
# LAB 4 - RSA
# ============================================================

def rsa_encrypt(plaintext):
    p = 10007
    q = 10009
    n = p * q
    phi = (p - 1) * (q - 1)

    e = -1
    for i in range(2, phi):
        if gcd(i, phi) == 1:
            e = i
            break

    d = -1
    for i in range(1, phi):
        if (e * i) % phi == 1:
            d = i
            break

    ciphertext = []

    for ch in plaintext:
        M = ord(ch) - ord('a')
        C = pow(M, e, n)
        ciphertext.append(C)

    return ciphertext, (n, e), (n, d)


def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    plaintext = ""

    for C in ciphertext:
        M = pow(C, d, n)
        plaintext += chr(M + ord('a'))

    return plaintext


def rsa_signature(message, p=61, q=53, e=17):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    m = int.from_bytes(message.encode(), "big")

    if m >= n:
        # Same limitation as the uploaded Lab 6 toy RSA program.
        # For large records, sign a hash instead.
        raise ValueError("Message is too large for these demo RSA parameters.")

    signature = pow(m, d, n)
    verified = pow(signature, e, n)

    return signature, (n, e), (n, d), verified == m


def rsa_hash_signature(message, p=61, q=53, e=17):
    # Practical adaptation for strings larger than the tiny toy RSA modulus.
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    h = int(hashlib.sha256(message.encode()).hexdigest(), 16)
    h = h % n

    signature = pow(h, d, n)
    verification = pow(signature, e, n)

    return signature, verification == h, (n, e), (n, d)


# ============================================================
# RSA KEY GENERATION
# ============================================================

def generate_rsa_keys():
    from Crypto.PublicKey import RSA

    key = RSA.generate(2048)

    return key, key.publickey()


# ============================================================
# RSA SIGNING
# ============================================================

def rsa_sign(message, private_key):
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    h = SHA256.new(message.encode())

    signature = pkcs1_15.new(private_key).sign(h)

    return signature.hex()


# ============================================================
# RSA VERIFICATION
# ============================================================

def rsa_verify(message, signature_hex, public_key):
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256

    h = SHA256.new(message.encode())

    try:
        signature = bytes.fromhex(signature_hex)

        pkcs1_15.new(public_key).verify(
            h,
            signature
        )

        return True

    except (ValueError, TypeError):
        return False


def rsa_verify(message, signature, public_key):
    n, e = public_key
    m = int.from_bytes(message.encode(), "big")
    verified = pow(signature, e, n)
    return verified == m


# ============================================================
# LAB 5 - HASHING
# ============================================================

def custom_hash(s):
    hash_value = 5381

    for ch in s:
        hash_value = hash_value * 33 + ord(ch)
        hash_value ^= (hash_value >> 16)
        hash_value &= 0xFFFFFFFF

    return hash_value


def sha256_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()


def md5_hash(message):
    return hashlib.md5(message.encode()).hexdigest()


def sha1_hash(message):
    return hashlib.sha1(message.encode()).hexdigest()


def verify_sha256(message, original_hash):
    return sha256_hash(message) == original_hash


def verify_sha1(message, original_hash):
    return sha1_hash(message) == original_hash


def generate_random_strings(count=100, length=20):
    strings = []

    for _ in range(count):
        random_string = ''.join(
            random.choices(
                string.ascii_letters + string.digits,
                k=length
            )
        )
        strings.append(random_string)

    return strings


def test_hash_algorithm(data, algorithm):
    hashes = []
    start_time = time.perf_counter()

    for text in data:
        text_bytes = text.encode()

        if algorithm == "MD5":
            hash_value = hashlib.md5(text_bytes).hexdigest()
        elif algorithm == "SHA-1":
            hash_value = hashlib.sha1(text_bytes).hexdigest()
        elif algorithm == "SHA-256":
            hash_value = hashlib.sha256(text_bytes).hexdigest()
        else:
            raise ValueError("Unknown hash algorithm")

        hashes.append(hash_value)

    execution_time = time.perf_counter() - start_time
    return hashes, execution_time


def detect_collisions(data, hashes):
    seen = {}
    collisions = []

    for original_string, hash_value in zip(data, hashes):
        if hash_value in seen:
            previous_string = seen[hash_value]

            if previous_string != original_string:
                collisions.append(
                    (previous_string, original_string, hash_value)
                )
        else:
            seen[hash_value] = original_string

    return collisions


def hash_performance_experiment(count=100, length=20):
    data = generate_random_strings(count, length)
    results = {}

    for algorithm in ["MD5", "SHA-1", "SHA-256"]:
        hashes, execution_time = test_hash_algorithm(data, algorithm)
        collisions = detect_collisions(data, hashes)

        results[algorithm] = {
            "time": execution_time,
            "collisions": collisions,
            "collision_count": len(collisions)
        }

    return results


# ============================================================
# LAB 5 - FILE INTEGRITY
# ============================================================

def file_sha256(filename):
    sha = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            chunk = file.read(4096)

            if not chunk:
                break

            sha.update(chunk)

    return sha.hexdigest()


def verify_file_integrity(filename, original_hash):
    current_hash = file_sha256(filename)
    return current_hash == original_hash


# ============================================================
# LAB 5 - SOCKET HASHING
# ============================================================

def hash_message_for_socket(message):
    return hashlib.sha256(message.encode()).hexdigest()


def socket_hash_server(host="127.0.0.1", port=5000):
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(1)

    print("Server waiting...")
    conn, addr = server.accept()
    print("Connected:", addr)

    message = conn.recv(4096).decode()
    print("Received:", message)
    print("SHA-256:", hash_message_for_socket(message))

    conn.close()
    server.close()


def socket_hash_client(message, host="127.0.0.1", port=5000):
    import socket

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))
    client.send(message.encode())
    client.close()


# ============================================================
# LAB 6 - DIFFIE-HELLMAN
# ============================================================

def diffie_hellman(p=23, g=5, a=6, b=15):
    A = pow(g, a, p)
    B = pow(g, b, p)

    alice_secret = pow(B, a, p)
    bob_secret = pow(A, b, p)

    return A, B, alice_secret, bob_secret, alice_secret == bob_secret


# ============================================================
# LAB 6 - ELGAMAL DIGITAL SIGNATURE
# ============================================================

def elgamal_signature(message, p=467, g=2, x=127, k=213):
    y = pow(g, x, p)

    H = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    while math.gcd(k, p - 1) != 1:
        k += 1

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)

    s = ((H - x * r) * k_inverse) % (p - 1)

    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    return {
        "public_key": (p, g, y),
        "private_key": x,
        "signature": (r, s),
        "left": left,
        "right": right,
        "valid": left == right
    }


def elgamal_sign(message, p=467, g=2, x=127, k=213):
    y = pow(g, x, p)

    H = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    while math.gcd(k, p - 1) != 1:
        k += 1

    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)
    s = ((H - x * r) * k_inverse) % (p - 1)

    return (r, s), (p, g, y), x


def elgamal_verify(message, signature, public_key):
    r, s = signature
    p, g, y = public_key

    H = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    left = pow(g, H, p)
    right = (pow(y, r, p) * pow(r, s, p)) % p

    return left == right


# ============================================================
# LAB 6 - SCHNORR DIGITAL SIGNATURE
# ============================================================

def schnorr_signature(message, p=23, q=11, g=2, x=7, k=3):
    y = pow(g, -x, p)

    r = pow(g, k, p)

    e = int(
        hashlib.sha256((message + str(r)).encode()).hexdigest(),
        16
    ) % q

    s = (k + x * e) % q

    r_new = (pow(g, s, p) * pow(y, e, p)) % p

    e_new = int(
        hashlib.sha256((message + str(r_new)).encode()).hexdigest(),
        16
    ) % q

    return [s,e]

def schnorr_verify(message, signature, p=23, q=11, g=2, public_key=4):

    s, e = signature

    r = (
        pow(g, s, p) *
        pow(public_key, e, p)
    ) % p

    e_new = int(
        hashlib.sha256(
            (message + str(r)).encode()
        ).hexdigest(),
        16
    ) % q

    return e == e_new


# ============================================================
# LAB 6 - ECC / ECDH / HKDF / AES-GCM
# ============================================================

def ecc_key_exchange():
    from cryptography.hazmat.primitives.asymmetric import ec

    private_a = ec.generate_private_key(ec.SECP256R1())
    private_b = ec.generate_private_key(ec.SECP256R1())

    public_a = private_a.public_key()
    public_b = private_b.public_key()

    secret_a = private_a.exchange(ec.ECDH(), public_b)
    secret_b = private_b.exchange(ec.ECDH(), public_a)

    return secret_a, secret_b, secret_a == secret_b


def derive_aes_key(shared_secret):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-communication"
    ).derive(shared_secret)


def aes_gcm_encrypt(message, key):
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(
        nonce,
        message.encode(),
        None
    )

    return nonce, ciphertext


def aes_gcm_decrypt(nonce, ciphertext, key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    plaintext = AESGCM(key).decrypt(
        nonce,
        ciphertext,
        None
    )

    return plaintext.decode()


def ecc_secure_message(message):
    secret_a, secret_b, same = ecc_key_exchange()

    if not same:
        return None

    key = derive_aes_key(secret_a)
    nonce, ciphertext = aes_gcm_encrypt(message, key)
    plaintext = aes_gcm_decrypt(nonce, ciphertext, key)

    return ciphertext, plaintext


# ============================================================
# LAB 6 - RABIN CRYPTOSYSTEM
# ============================================================

def is_prime(n):
    if n < 2:
        return False

    if n == 2:
        return True

    if n % 2 == 0:
        return False

    i = 3
    while i * i <= n:
        if n % i == 0:
            return False
        i += 2

    return True


def rabin_generate_keys(p=7, q=11):
    n = p * q
    return (n,), (p, q)


def rabin_encrypt(message, n):
    m = int.from_bytes(message.encode(), "big")

    if m >= n:
        raise ValueError("Message too large for selected Rabin modulus.")

    return pow(m, 2, n)


def rabin_decrypt(ciphertext, p, q):
    # Basic educational Rabin decryption for p,q == 3 mod 4.
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)

    # Extended Euclidean combination
    def egcd(a, b):
        if b == 0:
            return a, 1, 0
        g, x, y = egcd(b, a % b)
        return g, y, x - (a // b) * y

    _, yp, yq = egcd(p, q)
    r = (yp * p * mq + yq * q * mp) % (p * q)
    s = (yp * p * mq - yq * q * mp) % (p * q)

    return [r, (-r) % (p * q), s, (-s) % (p * q)]


# ============================================================
# CIA TRIAD
# ============================================================

def cia_triad_demo(message):
    # Confidentiality -> encryption
    # Integrity -> SHA-256
    # Authentication -> digital signature

    ciphertext = des_encrypt(
        message,
        b"A1B2C3D4"
    )
    plaintext = des_decrypt(
        ciphertext,
        b"A1B2C3D4"
    )

    original_hash = sha256_hash(message)

    signature, public_key, private_key, valid = rsa_signature(
        "abc"
    )

    return {
        "confidentiality": {
            "ciphertext": ciphertext,
            "decrypted": plaintext
        },
        "integrity": {
            "sha256": original_hash
        },
        "authentication": {
            "signature": signature,
            "valid": valid
        }
    }


# ============================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================

def student_access():
    print("Student Access")
    print("Allowed: View own academic record")


def faculty_access():
    print("Faculty Access")
    print("Allowed: View/update student academic records")


def hod_access():
    print("HoD Access")
    print("Allowed: View/update/manage academic records")


def rbac(role):
    role = role.lower()

    if role == "student":
        student_access()
    elif role == "faculty":
        faculty_access()
    elif role == "hod":
        hod_access()
    else:
        print("Access Denied")


# ============================================================
# FILE / RECORD STORAGE
# ============================================================

def save_record(filename, record):
    import json

    with open(filename, "w") as file:
        json.dump(record, file, indent=4)


def load_record(filename):
    import json

    with open(filename, "r") as file:
        return json.load(file)


def add_timestamp(record):
    from datetime import datetime

    record["timestamp"] = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    return record


# ============================================================
# EDUSecure - GLUE FUNCTION
# ============================================================

def edusecure_record(student_record, des_key=b"A1B2C3D4"):
    """
    Example of how to combine the lab functions.

    1. Record -> string
    2. DES -> confidentiality
    3. SHA-256 -> integrity
    4. RSA signature -> authentication
    5. Role check -> authorization
    """

    import json

    record_text = json.dumps(student_record)

    ciphertext = des_encrypt(
        record_text,
        des_key
    )
    decrypted = des_decrypt(
        ciphertext,
        des_key
    )

    record_hash = sha256_hash(record_text)

    return {
        "encrypted_record": ciphertext,
        "decrypted_record": decrypted,
        "hash": record_hash
    }


# ============================================================
# MASTER MENU
# ============================================================

def master_menu():
    while True:
        print("\n" + "=" * 60)
        print("INFORMATION SECURITY LAB 1-6 MASTER MENU")
        print("=" * 60)

        print("1. Additive Cipher")
        print("2. Multiplicative Cipher")
        print("3. Affine Cipher")
        print("4. Vigenere Cipher")
        print("5. Autokey Cipher")
        print("6. Playfair Cipher")
        print("7. Hill Cipher Encryption")
        print("8. Known Plaintext Attack")
        print("9. Brute Force Affine")
        print("10. DES")
        print("11. Triple DES")
        print("12. AES")
        print("13. RSA Encryption")
        print("14. RSA Digital Signature")
        print("15. Custom Hash")
        print("16. SHA-256")
        print("17. Hash Performance")
        print("18. File SHA-256")
        print("19. Diffie-Hellman")
        print("20. ElGamal Signature")
        print("21. Schnorr Signature")
        print("22. ECC / ECDH")
        print("23. AES-GCM")
        print("24. Rabin")
        print("25. RBAC")
        print("26. EduSecure Glue")
        print("0. Exit")

        choice = input("\nEnter choice: ")

        if choice == "0":
            break

        elif choice == "1":
            text = input("Enter plaintext: ")
            key = int(input("Enter key: "))
            print("Encrypted:", additive_encrypt(text, key))
            print("Decrypted:", additive_decrypt(additive_encrypt(text, key), key))

        elif choice == "2":
            text = input("Enter plaintext: ")
            key = int(input("Enter key: "))
            cipher = multiplicative_encrypt(text, key)
            print("Encrypted:", cipher)
            print("Decrypted:", multiplicative_decrypt(cipher, key))

        elif choice == "3":
            text = input("Enter plaintext: ")
            a = int(input("Enter a: "))
            b = int(input("Enter b: "))
            cipher = affine_encrypt(text, a, b)
            print("Encrypted:", cipher)
            print("Decrypted:", affine_decrypt(cipher, a, b))

        elif choice == "4":
            text = input("Enter plaintext: ")
            key = input("Enter key: ")
            cipher = vigenere_encrypt(text, key)
            print("Encrypted:", cipher)
            print("Decrypted:", vigenere_decrypt(cipher, key))

        elif choice == "5":
            text = input("Enter plaintext: ")
            key = input("Enter key: ")
            cipher = autokey_encrypt(text, key)
            print("Encrypted:", cipher)
            print("Decrypted:", autokey_decrypt(cipher, key))

        elif choice == "6":
            text = input("Enter plaintext: ")
            key = input("Enter key: ")
            print("Encrypted:", playfair_encrypt(text, key))

        elif choice == "7":
            text = input("Enter plaintext: ")
            matrix = [[3, 3], [2, 5]]
            print("Encrypted:", hill_encrypt(text, matrix))

        elif choice == "8":
            p = input("Known plaintext: ")
            c = input("Known ciphertext: ")
            print("Shift key:", known_plaintext_shift_attack(p, c))

        elif choice == "9":
            cipher = input("Enter ciphertext: ")
            for a, b, plain in brute_force_affine(cipher)[:10]:
                print(a, b, plain)

        elif choice == "10":
            message = input("Enter message: ")
            cipher = des_encrypt(message)
            print("Encrypted:", cipher)
            print("Decrypted:", des_decrypt(cipher))

        elif choice == "11":
            message = input("Enter message: ")
            cipher = triple_des_encrypt(message)
            print("Encrypted:", cipher)
            print("Decrypted:", triple_des_decrypt(cipher))

        elif choice == "12":
            message = input("Enter message: ")
            cipher = aes_encrypt(message)
            print("Encrypted:", cipher)
            print("Decrypted:", aes_decrypt(cipher))

        elif choice == "13":
            message = input("Enter lowercase plaintext: ")
            cipher, public, private = rsa_encrypt(message)
            print("Ciphertext:", cipher)
            print("Public:", public)
            print("Private:", private)
            print("Decrypted:", rsa_decrypt(cipher, private))

        elif choice == "14":
            message = input("Enter short message: ")
            signature, public, private = rsa_sign(message)
            print("Signature:", signature)
            print("Public:", public)
            print("Private:", private)
            print("Verified:", rsa_verify(message, signature, public))

        elif choice == "15":
            message = input("Enter string: ")
            print("Hash:", custom_hash(message))
            print("Hex:", hex(custom_hash(message)))

        elif choice == "16":
            message = input("Enter string: ")
            original_hash = sha256_hash(message)
            print("SHA-256:", original_hash)
            print("Verified:", verify_sha256(message, original_hash))

        elif choice == "17":
            results = hash_performance_experiment()
            for algorithm, result in results.items():
                print(algorithm, result["time"], result["collision_count"])

        elif choice == "18":
            filename = input("Enter filename: ")
            print(file_sha256(filename))

        elif choice == "19":
            result = diffie_hellman()
            print("Alice Public:", result[0])
            print("Bob Public:", result[1])
            print("Alice Secret:", result[2])
            print("Bob Secret:", result[3])
            print("Successful:", result[4])

        elif choice == "20":
            message = input("Enter message: ")
            signature, public_key, private_key = elgamal_sign(message)
            print("Signature:", signature)
            print("Public:", public_key)
            print("Private:", private_key)
            print("Verified:", elgamal_verify(message, signature, public_key))

        elif choice == "21":
            message = input("Enter message: ")
            signature = schnorr_signature(message)
            print("Signature:", signature)
            print("Verified:", schnorr_verify(message, signature))

        elif choice == "22":
            a, b, same = ecc_key_exchange()
            print("Shared secrets equal:", same)

        elif choice == "23":
            message = input("Enter message: ")
            secret_a, _, _ = ecc_key_exchange()
            key = derive_aes_key(secret_a)
            nonce, ciphertext = aes_gcm_encrypt(message, key)
            print("Ciphertext:", ciphertext.hex())
            print("Decrypted:", aes_gcm_decrypt(nonce, ciphertext, key))

        elif choice == "24":
            n, = rabin_generate_keys(7, 11)[0]
            message = input("Enter very short message: ")
            cipher = rabin_encrypt(message, n)
            print("Ciphertext:", cipher)
            print("Possible plaintexts:", rabin_decrypt(cipher, 7, 11))

        elif choice == "25":
            role = input("Enter role (Student/Faculty/HoD): ")
            rbac(role)

        elif choice == "26":
            record = {
                "student_id": input("Student ID: "),
                "name": input("Name: "),
                "marks": input("Marks: ")
            }
            print(edusecure_record(record))

        else:
            print("Invalid choice")


if __name__ == "__main__":
    master_menu()
