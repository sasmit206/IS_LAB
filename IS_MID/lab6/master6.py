import hashlib
import math
import socket


# ============================================================
# 1. RSA DIGITAL SIGNATURE
# ============================================================

# def rsa_signature():
#     print("\n--- RSA DIGITAL SIGNATURE ---")

#     # Small educational RSA values
#     p = 61
#     q = 53
#     e = 17

#     n = p * q
#     phi = (p - 1) * (q - 1)

#     # Private exponent
#     d = pow(e, -1, phi)

#     message = input("Enter message: ")

#     # Convert message to an integer
#     m = int.from_bytes(message.encode(), "big")

#     if m >= n:
#         print("Message is too large for these demo RSA parameters.")
#         return

#     # Sign using private key
#     signature = pow(m, d, n)

#     # Verify using public key
#     verified = pow(signature, e, n)

#     print("Public Key :", (n, e))
#     print("Private Key:", (n, d))
#     print("Signature  :", signature)

#     if verified == m:
#         print("Digital Signature VALID")
#     else:
#         print("Digital Signature INVALID")


# ============================================================
# 2. ELGAMAL DIGITAL SIGNATURE
# ============================================================

def elgamal_signature():
    print("\n--- ELGAMAL DIGITAL SIGNATURE ---")

    # Public parameters
    p = 467
    g = 2

    # Private key
    x = 127

    # Public key
    y = pow(g, x, p)

    message = input("Enter message: ")

    # Hash the message
    H = int(
        hashlib.sha256(message.encode()).hexdigest(),
        16
    )

    # Temporary signing value
    k = 213

    while math.gcd(k, p - 1) != 1:
        k += 1

    # Generate signature
    r = pow(g, k, p)
    k_inverse = pow(k, -1, p - 1)

    s = ((H - x * r) * k_inverse) % (p - 1)

    print("Public Key:", (p, g, y))
    print("Signature :", (r, s))

    # Verification
    v1 = pow(g, H, p)
    v2 = (pow(y, r, p) * pow(r, s, p)) % p

    if v1 == v2:
        print("Digital Signature VALID")
    else:
        print("Digital Signature INVALID")


# ============================================================
# 3. SCHNORR DIGITAL SIGNATURE
# ============================================================

def schnorr_signature():
    print("\n--- SCHNORR DIGITAL SIGNATURE ---")

    # Public parameters
    p = 23
    q = 11
    g = 2

    # Private key
    x = 7

    # Public key
    y = pow(g, -x, p)

    message = input("Enter message: ")

    # Temporary signing value
    k = 3

    # Commitment
    r = pow(g, k, p)

    # Challenge
    e = int(
        hashlib.sha256(
            (message + str(r)).encode()
        ).hexdigest(),
        16
    ) % q

    # Signature
    s = (k + x * e) % q

    print("Public Key:", y)
    print("Signature :", (s, e))

    # Reconstruct commitment
    r_new = (
        pow(g, s, p) *
        pow(y, e, p)
    ) % p

    # Calculate challenge again
    e_new = int(
        hashlib.sha256(
            (message + str(r_new)).encode()
        ).hexdigest(),
        16
    ) % q

    if e == e_new:
        print("Digital Signature VALID")
    else:
        print("Digital Signature INVALID")


# ============================================================
# 4. DIFFIE-HELLMAN KEY EXCHANGE
# ============================================================

def diffie_hellman():
    print("\n--- DIFFIE-HELLMAN KEY EXCHANGE ---")

    # Public values
    p = 23
    g = 5

    # Private keys
    a = 6
    b = 15

    # Public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    print("Alice Public Key:", A)
    print("Bob Public Key:", B)

    # Calculate shared secret
    alice_secret = pow(B, a, p)
    bob_secret = pow(A, b, p)

    print("Alice Shared Secret:", alice_secret)
    print("Bob Shared Secret:", bob_secret)

    if alice_secret == bob_secret:
        print("Key Exchange Successful")
    else:
        print("Key Exchange Failed")


# ============================================================
# 5. CLIENT-SERVER HASH / INTEGRITY DEMONSTRATION
# ============================================================

def server():
    print("\n--- SERVER ---")

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.bind(("localhost", 4000))
    server_socket.listen(1)

    print("Server waiting for connection...")

    connection, address = server_socket.accept()

    print("Connected:", address)

    data = connection.recv(1024)

    print("Received:", data.decode())

    # Calculate SHA-256 hash
    server_hash = hashlib.sha256(data).hexdigest()

    print("Server Hash:", server_hash)

    connection.sendall(server_hash.encode())

    connection.close()
    server_socket.close()


def client():
    print("\n--- CLIENT ---")

    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    client_socket.connect(("localhost", 4000))

    message = input("Enter message: ")

    data = message.encode()

    # Calculate hash before transmission
    local_hash = hashlib.sha256(data).hexdigest()

    client_socket.sendall(data)

    server_hash = client_socket.recv(1024).decode()

    print("Client Hash :", local_hash)
    print("Server Hash :", server_hash)

    if local_hash == server_hash:
        print("Data Integrity Verified")
    else:
        print("Data Integrity Check Failed")

    client_socket.close()


def client_server():
    print("\nRun this function separately on two terminals.")
    print("Terminal 1 → server()")
    print("Terminal 2 → client()")


# ============================================================
# 6. CIA TRIAD
# ============================================================

def cia_triad():
    print("\n--- CIA TRIAD ---")

    message = input("Enter message: ").encode()

    # ---------------- INTEGRITY ----------------

    digest = hashlib.sha256(message).hexdigest()

    print("\nSHA-256 Hash:")
    print(digest)

    # ---------------- AUTHENTICATION ----------------

    # Simple demonstration of a digital signature
    p = 61
    q = 53
    e = 17

    n = p * q
    phi = (p - 1) * (q - 1)

    d = pow(e, -1, phi)

    m = int.from_bytes(message, "big")

    if m >= n:
        print("\nMessage too large for demo RSA parameters.")
        return

    signature = pow(m, d, n)

    verified = pow(signature, e, n)

    if verified == m:
        print("Digital Signature: VALID")
    else:
        print("Digital Signature: INVALID")

    # ---------------- CONFIDENTIALITY ----------------

    encrypted = pow(m, e, n)
    decrypted = pow(encrypted, d, n)

    print("Encrypted Message:", encrypted)
    print(
        "Decrypted Message:",
        decrypted.to_bytes(
            (decrypted.bit_length() + 7) // 8,
            "big"
        ).decode()
    )

    print("\nCIA demonstration completed.")


# ============================================================
# MAIN PROGRAM
# ============================================================

while True:

    print("\n==============================")
    print("        LAB 6")
    print("    DIGITAL SIGNATURE")
    print("==============================")

    print("1. RSA Digital Signature")
    print("2. ElGamal Digital Signature")
    print("3. Schnorr Digital Signature")
    print("4. Diffie-Hellman")
    print("5. Client")
    print("6. Server")
    print("7. CIA Triad")
    print("8. Exit")

    choice = int(input("\nEnter choice: "))

    if choice == 1:
        rsa_signature()

    elif choice == 2:
        elgamal_signature()

    elif choice == 3:
        schnorr_signature()

    elif choice == 4:
        diffie_hellman()

    elif choice == 5:
        client()

    elif choice == 6:
        server()

    elif choice == 7:
        cia_triad()

    elif choice == 8:
        print("Exiting...")
        break

    else:
        print("Invalid choice")