# Practice Question — Secure Research Archive

# A university maintains a Research Archive System where researchers upload 
# confidential experimental records. 
# The system has three roles: Researcher, Reviewer, and Administrator.

# When a researcher uploads a record, the system should:
# Encrypt the record using AES for confidentiality.
# Generate a SHA-256 hash of the original record for integrity verification.
# Generate an RSA digital signature on the hash for authentication.
# Store the encrypted record, hash, signature, researcher name, and timestamp 
# in a JSON file.

# Allow a Reviewer to view stored records and verify:
# whether the SHA-256 hash still matches,
# whether the RSA signature is valid.

# Allow an Administrator to view all records and manage access according to role.

# Provide a menu-driven interface with separate functions for encryption/decryption,
#  hashing/verification, RSA signing/verification, JSON storage, timestamping, and 
# role-based access control.

# Algorithms required
# AES → Encryption / Decryption
# SHA-256 → Hashing / Verification
# RSA → Digital Signature / Verification
# JSON → Record Storage
# RBAC → Authorization
# Timestamp → Record tracking
import json
import hashlib
from datetime import datetime

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

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

# ============================================================
# 2. STORAGE FUNCTIONS
# ============================================================

DATABASE_FILE = "records.json"
def load_records():
    try:
        with open(DATABASE_FILE, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return []


def save_records(records):
    with open(DATABASE_FILE, "w") as file:
        json.dump(records, file, indent=4)

# ============================================================
# 2. RESEARCHER FUNCTIONS
# ============================================================

def sha256_hash(message):
    return hashlib.sha256(message.encode()).hexdigest()

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

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def researcher_upload(researcher_name, private_key):

    print("\n===== UPLOAD RESEARCHER RECORD =====")

    record = input("Enter research record: ")

    # Encrypt record using 3DES
    encrypted_record = aes_encrypt(
        record
    )

    # Hash original plaintext
    plaintext_hash = sha256_hash(record)

    # Hash encrypted record
    encrypted_hash = sha256_hash(
        encrypted_record
    )

    # Sign encrypted hash
    signature = rsa_sign(
        encrypted_hash,
        private_key
    )

    # Create record
    new_record = {
        "researcher": researcher_name,
        "encrypted_record": encrypted_record,
        "plaintext_hash": plaintext_hash,
        "encrypted_hash": encrypted_hash,
        "signature": signature,
        "timestamp": get_timestamp()
    }

    # Save
    records = load_records()

    records.append(new_record)

    save_records(records)

    print("\nRecord uploaded successfully.")
    print("SHA-1 Hash:", plaintext_hash)
    print("RSA Signature:", signature)
    print("Timestamp:", new_record["timestamp"])

def researcher_view(researcher_name):

    print("\n===== MY RECORDS =====")

    records = load_records()

    found = False

    for record in records:

        if record["researcher"] == researcher_name:

            found = True

            print("\nResearcher:", record["patient"])
            print("Encrypted Record:",
                  record["encrypted_record"])
            print("SHA-1 Hash:",
                  record["plaintext_hash"])
            print("Timestamp:",
                  record["timestamp"])

    if not found:
        print("No records found.")

def researcher_menu(private_key):

    researcher_name = input("\nEnter researcher name: ")

    while True:

        print("\n===== PATIENT MENU =====")
        print("1. Upload Record")
        print("2. View My Records")
        print("3. Logout")

        choice = input("Enter choice: ")

        if choice == "1":

            researcher_upload(
                researcher_name,
                private_key
            )

        elif choice == "2":

            researcher_view(researcher_name)

        elif choice == "3":

            break

        else:

            print("Invalid choice.")


# ============================================================
# ADMIN Functions
# ============================================================

def admin_view(public_key):

    print("\n===== ADMIN RECORD VERIFICATION =====")

    records = load_records()

    if len(records) == 0:

        print("No records found.")

        return

    for record in records:

        print("\n--------------------------------")
        print("Researcher:", record["researcher"])

        print(
            "Plaintext SHA256:",
            record["plaintext_hash"]
        )

        print(
            "Encrypted SHA256:",
            record["encrypted_hash"]
        )

        print(
            "RSA Signature:",
            record["signature"]
        )

        # Admin can verify signature
        # but does NOT have the DES key

        valid = rsa_verify(
            record["encrypted_hash"],
            record["signature"],
            public_key
        )

        print(
            "Signature:",
            "VALID" if valid else "INVALID"
        )

        print(
            "Timestamp:",
            record["timestamp"]
        )



def admin_menu(public_key):

    while True:

        print("\n===== ADMIN MENU =====")
        print("1. View Hashes and Signatures")
        print("2. Logout")

        choice = input("Enter choice: ")

        if choice == "1":

            admin_view(public_key)

        elif choice == "2":

            break

        else:

            print("Invalid choice.")





# ============================================================
# Reviewer Functions
# ============================================================

def rsa_verify(message, signature, public_key):
    n, e = public_key
    m = int.from_bytes(message.encode(), "big")
    verified = pow(signature, e, n)
    return verified == m


def reviewer_verify(record, public_key):

    print("\n===== REVIEWER VERIFICATION =====")

    # Decrypt encrypted record
    decrypted_record = aes_decrypt(
        record["encrypted_record"]
    )

    print("\nDecrypted Record:")
    print(decrypted_record)

    # --------------------------------------------------------
    # SHA-1 VERIFICATION
    # --------------------------------------------------------

    calculated_hash = sha256_hash(
        decrypted_record
    )

    stored_hash = record["plaintext_hash"]

    hash_valid = (
        calculated_hash == stored_hash
    )

    print("\nSHA-1 Verification:",
          "VALID" if hash_valid else "INVALID")

    # --------------------------------------------------------
    # SCHNORR VERIFICATION
    # --------------------------------------------------------

    signature_valid = rsa_verify(
        record["encrypted_hash"],
        record["signature"],
        public_key
    )

    print(
        "RSA Signature:",
        "VALID" if signature_valid else "INVALID"
    )

    # --------------------------------------------------------
    # STORE VERIFICATION RESULT
    # --------------------------------------------------------

    record["hash_verification"] = hash_valid

    record["signature_verification"] = signature_valid

    record["verification_timestamp"] = get_timestamp()



def reviewer_menu(public_key):

    while True:

        print("\n===== REVIEWER MENU =====")
        print("1. View and Verify Records")
        print("2. Logout")

        choice = input("Enter choice: ")

        if choice == "1":

            records = load_records()

            if len(records) == 0:

                print("No records available.")

                continue

            for i, record in enumerate(records):

                print(
                    f"{i + 1}. "
                    f"{record['researcher']} "
                    f"({record['timestamp']})"
                )

            try:

                number = int(
                    input("Select record: ")
                )

                if number < 1 or number > len(records):

                    print("Invalid record.")

                    continue

            except ValueError:

                print("Enter a valid number.")

                continue

            reviewer_verify(
                records[number - 1],
                public_key
            )

            save_records(records)

        elif choice == "2":

            break

        else:

            print("Invalid choice.")


# ============================================================
# 17. ROLE BASED ACCESS CONTROL
# ============================================================

def role_based_access(private_key, public_key):

    while True:

        print("\n================================")
        print("       ArchiveEDU SYSTEM")
        print("================================")

        print("1. Researcher")
        print("2. Reviewer")
        print("3. Administrator")
        print("4. Exit")

        role = input("\nSelect role: ")

        if role == "1":

            researcher_menu(private_key)

        elif role == "2":

            reviewer_menu(public_key)

        elif role == "3":

            admin_menu(public_key)

        elif role == "4":

            print("Exiting ArchiveVault.")

            break

        else:

            print("Invalid role.")



# ============================================================
# 18. MAIN PROGRAM
# ============================================================

def main():

    # Generate Schnorr key pair
    private_key, public_key = generate_rsa_keys()

    print("SecureArchive started.")

    role_based_access(
        private_key,
        public_key
    )


# ============================================================
# 19. PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()
