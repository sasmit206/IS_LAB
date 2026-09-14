import os
import time

from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# =========================================================
# ECC KEY GENERATION
# =========================================================

def generate_ecc_keys():

    start = time.perf_counter()

    private_key = ec.generate_private_key(
        ec.SECP256R1()
    )

    public_key = private_key.public_key()

    end = time.perf_counter()

    return private_key, public_key, end - start


# =========================================================
# ECDH - GENERATE SHARED SECRET
# =========================================================

def generate_shared_secret(private_key, public_key):

    shared_secret = private_key.exchange(
        ec.ECDH(),
        public_key
    )

    return shared_secret


# =========================================================
# HKDF - DERIVE AES KEY
# =========================================================

def derive_aes_key(shared_secret):

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"Secure File Transfer"
    ).derive(shared_secret)

    return aes_key


# =========================================================
# ECC FILE ENCRYPTION
# =========================================================

def ecc_encrypt_file(data, sender_private_key, receiver_public_key):

    # Sender independently generates the shared secret
    sender_secret = generate_shared_secret(
        sender_private_key,
        receiver_public_key
    )

    # Derive AES key from shared secret
    sender_aes_key = derive_aes_key(
        sender_secret
    )

    # AES-GCM encryption
    aes = AESGCM(sender_aes_key)

    # Generate random nonce
    nonce = os.urandom(12)

    # Encrypt file data
    encrypted_data = aes.encrypt(
        nonce,
        data,
        None
    )

    return nonce, encrypted_data


# =========================================================
# ECC FILE DECRYPTION
# =========================================================

def ecc_decrypt_file(
        nonce,
        encrypted_data,
        receiver_private_key,
        sender_public_key):

    # Receiver independently generates the shared secret
    receiver_secret = generate_shared_secret(
        receiver_private_key,
        sender_public_key
    )

    # Derive the same AES key
    receiver_aes_key = derive_aes_key(
        receiver_secret
    )

    # AES-GCM decryption
    aes = AESGCM(receiver_aes_key)

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return decrypted_data


# =========================================================
# ECC BENCHMARK
# =========================================================

def benchmark_ecc(
        data,
        sender_private_key,
        sender_public_key,
        receiver_private_key,
        receiver_public_key):

    # -----------------------------------------------------
    # Encryption
    # -----------------------------------------------------

    start = time.perf_counter()

    nonce, encrypted_data = ecc_encrypt_file(
        data,
        sender_private_key,
        receiver_public_key
    )

    encryption_time = time.perf_counter() - start

    # -----------------------------------------------------
    # Decryption
    # -----------------------------------------------------

    start = time.perf_counter()

    decrypted_data = ecc_decrypt_file(
        nonce,
        encrypted_data,
        receiver_private_key,
        sender_public_key
    )

    decryption_time = time.perf_counter() - start

    return (
        encryption_time,
        decryption_time,
        decrypted_data
    )


#===================================
#RSA Key Generation
#===================================

def generate_rsa_keys():

    start = time.perf_counter()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    end = time.perf_counter()

    return private_key, public_key, end - start

def rsa_file_encrypt(data, receiver_public_key):

    #generate random 256 bit key
    aes_key = AESGCM.generate_key(bit_length=256)

    aes = AESGCM(aes_key)

    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(nonce,data,None)

    #protect aes key using RSA-2048

    encrypted_aes_key = receiver_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_aes_key, nonce, encrypted_data


def rsa_file_decrypt(nonce, encrypted_data, encrypted_aes_key, receiver_private_key):

    aes_key = receiver_private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #decrypt file using aes:
    aes = AESGCM(aes_key)

    decrypted_data = aes.decrypt(
        nonce,
        encrypted_data,
        None
    )

    return decrypted_data

def benchmark_rsa(data, private_key, public_key):

    #encryption:
    start = time.perf_counter()

    encrypted_key, nonce, encrypted_data = rsa_file_encrypt(data,public_key)

    end = time.perf_counter()

    encryption_time = end-start

    #decryption:

    start = time.perf_counter()

    decrypted_data = rsa_file_decrypt(nonce,encrypted_data,encrypted_key,private_key)

    end = time.perf_counter()

    decryption_time = end - start

    return (
        encryption_time,
        decryption_time,
        decrypted_data
    )


def create_test_file(size_mb):

    size = size_mb * 1024 * 1024

    return os.urandom(size)


def main():

    print("="*60)
    print("SECURE FILE TRANSFER - RSA vs ECC")
    print("="*60)

    #RSA key generation

    print("Generating RSA-2048 Keys...")
    rsa_private, rsa_public, rsa_key_time = generate_rsa_keys()

    print("RSA key generation time: ",rsa_key_time," seconds")

    #ECC key generation

    sender_ecc_private, sender_ecc_public, sender_ecc_time = generate_ecc_keys()

    receiver_ecc_private, receiver_ecc_public, receiver_ecc_time = generate_ecc_keys()

    ecc_key_time = sender_ecc_time + receiver_ecc_time

    print("ECC key generation time: ",ecc_key_time," seconds")

    for size in [1, 10]:
        print("\n" + "=" * 60)
        print(f"TESTING {size} MB FILE")
        print("=" * 60)

        data = create_test_file(size)

        # =================================================
        # RSA
        # =================================================

        print("\n--- RSA-2048 ---")

        rsa_enc, rsa_dec, rsa_result = benchmark_rsa(
            data,
            rsa_private,
            rsa_public
        )

        print("Encryption time:",
              rsa_enc, "seconds")

        print("Decryption time:",
              rsa_dec, "seconds")

        print("Verification:",
              rsa_result == data)

        # =================================================
        # ECC
        # =================================================

        print("\n--- ECC secp256r1 ---")

        ecc_enc, ecc_dec, ecc_result = benchmark_ecc(
            data,
            sender_ecc_private,
            sender_ecc_public,
            receiver_ecc_private,
            receiver_ecc_public
        )

        print("Encryption time:",
              ecc_enc, "seconds")

        print("Decryption time:",
              ecc_dec, "seconds")

        print("Verification:",
              ecc_result == data)

main()