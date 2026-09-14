import json
import os
from datetime import datetime

from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes


# =========================
# DES FUNCTIONS
# =========================

def pad(data):
    padding = 8 - (len(data) % 8)
    return data + bytes([padding]) * padding


def unpad(data):
    return data[:-data[-1]]


def des_encrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(data))


def des_decrypt(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(data))


# =========================
# SHA-256
# =========================

def calculate_hash(data):
    return SHA256.new(data).hexdigest()


# =========================
# RSA KEY GENERATION
# =========================

def generate_rsa_keys():
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    return private_key, public_key


# =========================
# RSA SIGNATURE
# =========================

def sign_hash(hash_string, private_key):
    key = RSA.import_key(private_key)

    hash_object = SHA256.new(hash_string.encode())

    signature = pkcs1_15.new(key).sign(hash_object)

    return signature.hex()


# =========================
# RSA VERIFICATION
# =========================

def verify_signature(hash_string, signature_hex, public_key):
    try:
        key = RSA.import_key(public_key)

        signature = bytes.fromhex(signature_hex)

        hash_object = SHA256.new(hash_string.encode())

        pkcs1_15.new(key).verify(hash_object, signature)

        return True

    except (ValueError, TypeError):
        return False


# =========================
# STORAGE
# =========================

DATABASE_FILE = "records.json"


def load_records():

    if not os.path.exists(DATABASE_FILE):
        return []

    with open(DATABASE_FILE, "r") as file:
        return json.load(file)


def save_records(records):

    with open(DATABASE_FILE, "w") as file:
        json.dump(records, file, indent=4)


# =========================
# STUDENT
# =========================

def student_upload(student_name, des_key, private_key):

    record = input("Enter academic record: ")

    plaintext = record.encode()

    # Encrypt using DES
    encrypted_data = des_encrypt(plaintext, des_key)

    # Hash original record
    plaintext_hash = calculate_hash(plaintext)

    # Hash encrypted record
    encrypted_hash = calculate_hash(encrypted_data)

    # Sign hash of encrypted record
    signature = sign_hash(encrypted_hash, private_key)

    records = load_records()

    new_record = {
        "student": student_name,
        "encrypted_record": encrypted_data.hex(),
        "plaintext_hash": plaintext_hash,
        "encrypted_hash": encrypted_hash,
        "signature": signature,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    records.append(new_record)

    save_records(records)

    print("\nRecord uploaded successfully.")
    print("SHA-256 hash:", plaintext_hash)
    print("Digital signature generated.")


def student_menu(student_name, des_key, private_key):

    while True:

        print("\n===== STUDENT MENU =====")
        print("1. Upload academic record")
        print("2. View records")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            student_upload(student_name, des_key, private_key)

        elif choice == "2":
            view_student_records(student_name)

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


def view_student_records(student_name):

    records = load_records()

    found = False

    for record in records:

        if record["student"] == student_name:

            found = True

            print("\nStudent:", record["student"])
            print("Encrypted record:", record["encrypted_record"])
            print("Hash:", record["plaintext_hash"])
            print("Timestamp:", record["timestamp"])

    if not found:
        print("No records found.")


# =========================
# FACULTY
# =========================

def faculty_verify(record, des_key, public_key):

    encrypted_data = bytes.fromhex(record["encrypted_record"])

    # Decrypt using DES
    decrypted_data = des_decrypt(encrypted_data, des_key)

    print("\nDecrypted record:")
    print(decrypted_data.decode())

    # Calculate hash of decrypted record
    calculated_hash = calculate_hash(decrypted_data)

    print("\nStored hash:", record["plaintext_hash"])
    print("Calculated hash:", calculated_hash)

    if calculated_hash == record["plaintext_hash"]:
        print("Hash verification: SUCCESS")
    else:
        print("Hash verification: FAILED")

    # Verify RSA signature
    valid_signature = verify_signature(
        record["encrypted_hash"],
        record["signature"],
        public_key
    )

    if valid_signature:
        print("RSA signature: VALID")
    else:
        print("RSA signature: INVALID")

    print("Verification timestamp:",
          datetime.now().strftime("%Y-%m-%d %H:%M:%S"))


def faculty_menu(des_key, public_key):

    records = load_records()

    if not records:
        print("No records available.")
        return

    print("\n===== RECORDS =====")

    for i, record in enumerate(records):
        print(i + 1, "-", record["student"],
              "-", record["timestamp"])

    choice = int(input("Select record: "))

    if 1 <= choice <= len(records):

        record = records[choice - 1]

        faculty_verify(record, des_key, public_key)

    else:
        print("Invalid record.")


# =========================
# HOD
# =========================

def hod_menu(public_key):

    records = load_records()

    if not records:
        print("No records available.")
        return

    while True:

        print("\n===== HOD MENU =====")
        print("1. View hashes")
        print("2. Verify signature")
        print("3. Exit")

        choice = input("Enter choice: ")

        if choice == "1":

            for record in records:

                print("\nStudent:", record["student"])
                print("SHA-256:", record["plaintext_hash"])
                print("Timestamp:", record["timestamp"])

        elif choice == "2":

            for i, record in enumerate(records):

                print(i + 1, "-", record["student"])

            number = int(input("Select record: "))

            if 1 <= number <= len(records):

                record = records[number - 1]

                valid = verify_signature(
                    record["encrypted_hash"],
                    record["signature"],
                    public_key
                )

                if valid:
                    print("RSA signature is VALID.")
                else:
                    print("RSA signature is INVALID.")

        elif choice == "3":
            break

        else:
            print("Invalid choice.")


# =========================
# MAIN
# =========================

def main():

    print("===== EDUSecure =====")

    # Shared DES key
    des_key = b"8bytekey"

    # Generate student's RSA keys
    private_key, public_key = generate_rsa_keys()

    student_name = input("Enter student name: ")

    while True:

        print("\n===== MAIN MENU =====")
        print("1. Student")
        print("2. Faculty")
        print("3. HoD")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == "1":

            student_menu(
                student_name,
                des_key,
                private_key
            )

        elif choice == "2":

            faculty_menu(
                des_key,
                public_key
            )

        elif choice == "3":

            hod_menu(public_key)

        elif choice == "4":

            print("Exiting EduSecure.")
            break

        else:
            print("Invalid choice.")


main()