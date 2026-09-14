# ============================================================
# MEDIVAULT - HOSPITAL PATIENT RECORD MANAGEMENT SYSTEM
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


# ============================================================
# 4. 3DES ENCRYPTION
# ============================================================

def triple_des_encrypt(message, key):
    cipher = DES3.new(key, DES3.MODE_ECB)

    padded_message = pad(message.encode(), DES3.block_size)

    encrypted = cipher.encrypt(padded_message)

    return encrypted.hex()


# ============================================================
# 5. 3DES DECRYPTION
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


# ============================================================
# 6. SHA-1 HASHING
# ============================================================

def sha1_hash(message):
    return hashlib.sha1(
        message.encode()
    ).hexdigest()


# ============================================================
# 7. SCHNORR KEY GENERATION
# ============================================================

def generate_schnorr_keys():
    private_key = 7

    public_key = pow(
        G,
        -private_key,
        P
    )

    return private_key, public_key


# ============================================================
# 8. SCHNORR DIGITAL SIGNATURE
# ============================================================

def schnorr_sign(message, private_key):

    # Random value used for demonstration
    k = 3

    # Commitment
    r = pow(G, k, P)

    # Challenge
    e = int(
        hashlib.sha256(
            (message + str(r)).encode()
        ).hexdigest(),
        16
    ) % Q

    # Signature
    s = (k + private_key * e) % Q

    return [s, e]


# ============================================================
# 9. SCHNORR SIGNATURE VERIFICATION
# ============================================================

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


# ============================================================
# 10. PATIENT - UPLOAD RECORD
# ============================================================

def patient_upload(patient_name, private_key):

    print("\n===== UPLOAD PATIENT RECORD =====")

    record = input("Enter patient record: ")

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
    signature = schnorr_sign(
        encrypted_hash,
        private_key
    )

    # Create record
    new_record = {
        "patient": patient_name,
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


# ============================================================
# 11. PATIENT - VIEW OWN RECORDS
# ============================================================

def patient_view(patient_name):

    print("\n===== MY RECORDS =====")

    records = load_records()

    found = False

    for record in records:

        if record["patient"] == patient_name:

            found = True

            print("\nPatient:", record["patient"])
            print("Encrypted Record:",
                  record["encrypted_record"])
            print("SHA-1 Hash:",
                  record["plaintext_hash"])
            print("Timestamp:",
                  record["timestamp"])

    if not found:
        print("No records found.")


# ============================================================
# 12. PATIENT MENU
# ============================================================

def patient_menu(private_key):

    patient_name = input("\nEnter patient name: ")

    while True:

        print("\n===== PATIENT MENU =====")
        print("1. Upload Record")
        print("2. View My Records")
        print("3. Logout")

        choice = input("Enter choice: ")

        if choice == "1":

            patient_upload(
                patient_name,
                private_key
            )

        elif choice == "2":

            patient_view(patient_name)

        elif choice == "3":

            break

        else:

            print("Invalid choice.")


# ============================================================
# 13. DOCTOR - VERIFY RECORD
# ============================================================

def doctor_verify(record, public_key):

    print("\n===== DOCTOR VERIFICATION =====")

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


# ============================================================
# 14. DOCTOR MENU
# ============================================================

def doctor_menu(public_key):

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
                    f"{record['patient']} "
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

            doctor_verify(
                records[number - 1],
                public_key
            )

            save_records(records)

        elif choice == "2":

            break

        else:

            print("Invalid choice.")


# ============================================================
# 15. ADMIN - VIEW HASHES
# ============================================================

def admin_view(public_key):

    print("\n===== ADMIN RECORD VERIFICATION =====")

    records = load_records()

    if len(records) == 0:

        print("No records found.")

        return

    for record in records:

        print("\n--------------------------------")
        print("Patient:", record["patient"])

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


# ============================================================
# 17. ROLE BASED ACCESS CONTROL
# ============================================================

def role_based_access(private_key, public_key):

    while True:

        print("\n================================")
        print("       MEDIVAULT SYSTEM")
        print("================================")

        print("1. Patient")
        print("2. Doctor")
        print("3. Hospital Administrator")
        print("4. Exit")

        role = input("\nSelect role: ")

        if role == "1":

            patient_menu(private_key)

        elif role == "2":

            doctor_menu(public_key)

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