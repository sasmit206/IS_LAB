# Question:

# You are tasked with developing a secure Research Data Management System called 
# ResearchVault.

# This system ensures that confidential research documents are stored securely, accessed
#  only by authorized users, and verified for authenticity and integrity. The system supports three types of users:
#  Researchers, Reviewers, and Research Administrators, each with specific roles and permissions.

# The platform uses 3DES symmetric encryption for storing sensitive research documents, 
# Schnorr digital signatures for authenticating documents, and SHA-1 hashing to verify document integrity.

# User Roles & Permissions

# Researcher:

# Encrypts a research document (for example: Climate_Research.txt) using 3DES before 
# uploading.
# Computes the SHA-1 hash of the encrypted document.
# Signs the SHA-1 hash using their Schnorr private key.
# Can view previously uploaded research documents along with their encrypted forms, 
# hashes, and timestamps.

# Reviewer:

# Decrypts the researcher's document using the shared 3DES key.
# Verifies the Schnorr digital signature of the document.
# Computes the SHA-1 hash of the decrypted document and compares it with the stored
#  hash.
# Stores the verification results along with a timestamp.

# Research Administrator:

# Can view only the hashed research documents along with timestamps.
# Can verify Schnorr digital signatures on stored documents for auditing purposes.
# Cannot decrypt or modify the research documents.
# Access Roles:
# Allow Researchers to encrypt documents using 3DES, generate Schnorr signatures, and 
# upload documents securely.
# Enable Reviewers to decrypt documents using 3DES, verify Schnorr signatures, and 
# verify document integrity using SHA-1.
# Allow Research Administrators to view hashes and verify signatures without accessing 
# the original documents.
# Task:

# Develop a menu-driven Python program that implements these functionalities using:

# 3DES symmetric encryption,
# Schnorr digital signatures, and
# SHA-1 hashing.

# Ensure secure handling of research documents and proper role-based access. Use any file
#  or database structure to store and retrieve the documents securely.




# ============================================================
# ResearchVault - RESEARCH RECORD MANAGEMENT SYSTEM
# ============================================================

import json
import hashlib
from datetime import datetime

from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad


# ============================================================
# 1. CONFIGURATION
# ============================================================

DATABASE_FILE = "records.json"

DES_KEY = b"123456789012345678901234"

# Schnorr parameters
P = 23
Q = 11
G = 2


# ============================================================
# 2. STORAGE FUNCTIONS
# ============================================================

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
# 3. TIMESTAMP FUNCTION
# ============================================================

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def generate_schnorr_keys():
    private_key = 7

    public_key = pow(
        G,
        -private_key,
        P
    )

    return private_key, public_key


def researcher_menu(private_key):

    researcher_name = input("\nEnter researcher name: ")

    while True:

        print("\n===== Researcher MENU =====")
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


def triple_des_encrypt(message, key=b"123456789012345678901234"):
    from Crypto.Cipher import DES3
    from Crypto.Util.Padding import pad

    cipher = DES3.new(key, DES3.MODE_ECB)
    ciphertext = cipher.encrypt(pad(message.encode(), 8))

    return ciphertext.hex()

def sha1_hash(message):
    return hashlib.sha1(message.encode()).hexdigest()

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

    return {
        "public_key": y,
        "signature": (s, e),
        "original_e": e,
        "new_e": e_new,
        "valid": e == e_new
    }


def researcher_upload(researcher_name, private_key):

    print("\n===== UPLOAD Researcher RECORD =====")

    record = input("Enter researcher record: ")

    # Encrypt record using 3DES
    encrypted_record = triple_des_encrypt(
        record,
        DES_KEY
    )

    # Hash original plaintext
    plaintext_hash = sha1_hash(record)

    # Hash encrypted record
    encrypted_hash = sha1_hash(
        encrypted_record
    )

    # Sign encrypted hash
    signature_result = schnorr_signature(
        encrypted_hash,
        private_key
    )

    signature = signature_result["signature"]

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
    print("Schnorr Signature:", signature)
    print("Timestamp:", new_record["timestamp"])

def researcher_view(researcher_name):

    print("\n===== MY RECORDS =====")

    records = load_records()

    found = False

    for record in records:

        if record["researcher"] == researcher_name:

            found = True

            print("\nResearcher:", record["researcher"])
            print("Encrypted Record:",
                  record["encrypted_record"])
            print("SHA-1 Hash:",
                  record["plaintext_hash"])
            print("Timestamp:",
                  record["timestamp"])

    if not found:
        print("No records found.")






# ============================================================
# 14. Reviewer MENU
# ============================================================

def triple_des_decrypt(ciphertext_hex, key):
    cipher = DES3.new(key, DES3.MODE_ECB)

    ciphertext = bytes.fromhex(ciphertext_hex)

    decrypted = cipher.decrypt(ciphertext)

    plaintext = unpad(
        decrypted,
        DES3.block_size
    ).decode()

    return plaintext

def schnorr_verify(message, signature, public_key):

    s = signature[0]
    e = signature[1]

    r = (
        pow(G, s, P) *
        pow(public_key, e, P)
    ) % P

    e_new = int(
        hashlib.sha256(
            (message + str(r)).encode()
        ).hexdigest(),
        16
    ) % Q

    return e == e_new

def reviewer_verify(record, public_key):

    print("\n===== Reviewer VERIFICATION =====")

    # Decrypt encrypted record
    decrypted_record = triple_des_decrypt(
        record["encrypted_record"],
        DES_KEY
    )

    print("\nDecrypted Record:")
    print(decrypted_record)

    # --------------------------------------------------------
    # SHA-1 VERIFICATION
    # --------------------------------------------------------

    calculated_hash = sha1_hash(
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

    signature_valid = schnorr_verify(
        record["encrypted_hash"],
        record["signature"],
        public_key
    )

    print(
        "Schnorr Signature:",
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

        print("\n===== DOCTOR MENU =====")
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
# 16. ADMIN MENU
# ============================================================

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
            "Plaintext SHA-1:",
            record["plaintext_hash"]
        )

        print(
            "Encrypted SHA-1:",
            record["encrypted_hash"]
        )

        print(
            "Schnorr Signature:",
            record["signature"]
        )

        # Admin can verify signature
        # but does NOT have the DES key

        valid = schnorr_verify(
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


# ============================================================
# 17. ROLE BASED ACCESS CONTROL
# ============================================================

def role_based_access(private_key, public_key):

    while True:

        print("\n================================")
        print("       Research SYSTEM")
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

            print("Exiting MediVault.")

            break

        else:

            print("Invalid role.")


# ============================================================
# 18. MAIN PROGRAM
# ============================================================

def main():

    # Generate Schnorr key pair
    private_key, public_key = generate_schnorr_keys()

    print("MediVault started.")

    role_based_access(
        private_key,
        public_key
    )


# ============================================================
# 19. PROGRAM START
# ============================================================

if __name__ == "__main__":
    main()