# INFORMATION SECURITY MIDSEM — MASTER CHEAT SHEET
#
# UNIVERSAL MAP
# CONFIDENTIALITY -> Encryption
# INTEGRITY -> Hash
# AUTHENTICATION -> Digital Signature
# KEY EXCHANGE -> DH / ECDH
# AUTHORIZATION -> RBAC
# STORAGE -> JSON
# FILE INTEGRITY -> File SHA-256
# SIGN -> PRIVATE KEY
# VERIFY -> PUBLIC KEY
#
# 1. STRING / BYTES / HEX
# message.encode()             str -> bytes
# data.decode()                bytes -> str
# data.hex()                   bytes -> hex str
# bytes.fromhex(data)          hex str -> bytes
#
# DES / 3DES / AES
# encrypt: str + bytes -> hex str
# decrypt: hex str + bytes -> str
# encrypt flow: encode -> pad -> encrypt -> hex
# decrypt flow: fromhex -> decrypt -> unpad -> decode
#
# 2. CLASSICAL CRYPTOGRAPHY
# ADDITIVE
# additive_encrypt(text,key): str,int -> str
# additive_decrypt(text,key): str,int -> str
# C=(P+K)%26
#
# MODULAR INVERSE
# mod_inverse(a,m): int,int -> int or None
#
# MULTIPLICATIVE
# multiplicative_encrypt(text,key): str,int -> str
# multiplicative_decrypt(text,key): str,int -> str or None
# C=(P*K)%26; gcd(K,26)=1
#
# AFFINE
# affine_encrypt(text,a,b): str,int,int -> str
# affine_decrypt(text,a,b): str,int,int -> str or None
# C=(aP+b)%26; P=a^-1(C-b)%26; gcd(a,26)=1
#
# VIGENERE
# vigenere_encrypt(text,key): str,str -> str
# vigenere_decrypt(text,key): str,str -> str
# C_i=(P_i+K_i)%26
# repeating keyword
#
# AUTOKEY
# autokey_encrypt(text,key): str,str -> str
# autokey_decrypt(ciphertext,key): str,str -> str
# initial key is extended using plaintext
#
# PLAYFAIR
# playfair_prepare(text): str -> str
# playfair_matrix(key): str -> 5x5 matrix
# playfair_encrypt(text,key): str,str -> str
# J->I; repeated pair -> X; odd length -> X
#
# HILL
# hill_encrypt(text,key_matrix): str,matrix -> str
# hill_decrypt(text,key_matrix): str,matrix -> str (current code: 2x2)
# C=KP mod 26
# K^-1 = det^-1 [ d -b ] mod 26 for K=[a b;c d]
#                         [ -c a ]
# determinant must be invertible mod 26
#
# 3. CRYPTANALYSIS
# known_plaintext_shift_attack(plaintext,ciphertext): str,str -> int or None
# K=C-P mod 26
# brute_force_affine(ciphertext): str -> list[(a,b,plaintext)]
#
# 4. DES / 3DES / AES
# des_encrypt(message,key=b"A1B2C3D4"): str,bytes -> hex str
# des_decrypt(ciphertext_hex,key=b"A1B2C3D4"): hex str,bytes -> str
# triple_des_encrypt(message,key=...): str,bytes -> hex str
# triple_des_decrypt(ciphertext_hex,key=...): hex str,bytes -> str
# aes_encrypt(message,key=...): str,bytes -> hex str
# aes_decrypt(ciphertext_hex,key=...): hex str,bytes -> str
# des_vs_aes_benchmark(message,rounds): str,int -> (des_time,aes_time) floats
#
# 5. RSA ENCRYPTION
# rsa_encrypt(plaintext): str -> (ciphertext list, public=(n,e), private=(n,d))
# rsa_decrypt(ciphertext,private_key): list[int],(n,d) -> str
# C=M^e mod n; M=C^d mod n
# public -> encrypt; private -> decrypt
#
# 6. RSA DIGITAL SIGNATURE
# generate_rsa_keys(): no input -> (private_key_object, public_key_object)
# rsa_sign(message,private_key): str,RSA private key -> signature hex str
# rsa_verify(message,signature_hex,public_key): str,hex str,RSA public key -> True/False
# SIGN with PRIVATE; VERIFY with PUBLIC
# Toy/manual versions also present:
# rsa_signature(message,p,q,e) -> signature,public,private,verified
# rsa_hash_signature(message,p,q,e) -> signature,verified,public,private
#
# 7. HASHING
# custom_hash(s): str -> int
# sha256_hash(message): str -> hex str
# sha1_hash(message): str -> hex str
# md5_hash(message): str -> hex str
# verify_sha256(message,original_hash): str,hex str -> True/False
# verify_sha1(message,original_hash): str,hex str -> True/False
# Hash verification = recompute hash and compare with stored hash
#
# HASH EXPERIMENT
# generate_random_strings(count,length): int,int -> list[str]
# test_hash_algorithm(data,algorithm): list[str],str -> (hashes,execution_time)
# detect_collisions(data,hashes): list[str],list[str] -> list[(old,new,hash)]
# hash_performance_experiment(count,length) -> dict with MD5/SHA-1/SHA-256 results
#
# 8. FILE INTEGRITY
# file_sha256(filename): str -> hex str
# verify_file_integrity(filename,original_hash): str,hex str -> True/False
# file -> SHA-256 -> compare
#
# 9. SOCKET HASHING
# hash_message_for_socket(message): str -> SHA-256 hex str
# socket_hash_server(host,port): str,int -> no important return
# socket_hash_client(message,host,port): str,str,int -> no important return
#
# 10. DIFFIE-HELLMAN
# diffie_hellman(p,g,a,b): int,int,int,int -> (A,B,alice_secret,bob_secret,same)
# A=g^a mod p
# B=g^b mod p
# SA=B^a mod p
# SB=A^b mod p
# same = SA==SB
# This is KEY EXCHANGE, not encryption/signature
#
# 11. ELGAMAL SIGNATURE
# elgamal_signature(message,p,g,x,k) -> dict with public_key,private_key,signature=(r,s),left,right,valid
# elgamal_sign(message,p,g,x,k) -> ((r,s),(p,g,y),x)
# elgamal_verify(message,signature,public_key) -> True/False
# sign -> (r,s); verify -> boolean
#
# 12. SCHNORR
# schnorr_signature(message,p,q,g,x,k) -> [s,e]
# schnorr_verify(message,signature,p,q,g,public_key) -> True/False
# signature[0]=s; signature[1]=e
# y=g^(-x) mod p
# r=g^k mod p
# e=H(message||r) mod q
# s=k+x*e mod q
#
# 13. ECC / ECDH / HKDF / AES-GCM
# ecc_key_exchange() -> (secret_a bytes, secret_b bytes, same bool)
# derive_aes_key(shared_secret bytes) -> 32-byte key
# aes_gcm_encrypt(message str,key bytes) -> (nonce bytes,ciphertext bytes)
# aes_gcm_decrypt(nonce bytes,ciphertext bytes,key bytes) -> plaintext str
# ecc_secure_message(message str) -> (ciphertext bytes, plaintext str)
# FLOW: ECDH -> shared secret -> HKDF -> AES key -> AES-GCM
# GCM gives confidentiality + authentication
#
# 14. RABIN
# is_prime(n): int -> True/False
# rabin_generate_keys(p,q): int,int -> ((n,), (p,q))
# rabin_encrypt(message,n): str,int -> ciphertext int
# rabin_decrypt(ciphertext,p,q): int,int,int -> list of 4 roots
# c=m^2 mod n; n=p*q; current decrypt shortcut assumes p,q == 3 mod 4
# current encryption also requires m<n because whole message becomes one integer
#
# 15. CIA TRIAD
# cia_triad_demo(message): str -> dict
# confidentiality -> encryption
# integrity -> SHA-256
# authentication -> digital signature
#
# 16. RBAC
# student_access(), faculty_access(), hod_access() -> prints permissions
# rbac(role): str -> no important return; prints allowed/denied
# role -> permission
#
# 17. JSON / RECORD STORAGE
# save_record(filename,record): str,dict -> None
# load_record(filename): str -> dict
# add_timestamp(record): dict -> same dict + record["timestamp"]
#
# 18. SCENARIO DECODER
# "confidential / secrecy" -> encryption
# "tamper / integrity / unchanged" -> hash + verification
# "prove sender / authenticity" -> digital signature + verification
# "shared secret" -> DH / ECDH
# "permissions / roles" -> RBAC
# "save to file" -> JSON
# "time/date" -> timestamp
#
# 19. FORMULA SHEET
# Additive:       C=(P+K) mod 26
# Multiplicative: C=(P*K) mod 26
# Affine:         C=(aP+b) mod 26
# RSA encrypt:    C=M^e mod n
# RSA decrypt:    M=C^d mod n
# DH:             A=g^a mod p, B=g^b mod p, S=g^(ab) mod p
# Rabin:          C=M^2 mod n
# Hill:           C=KP mod 26, P=K^-1 C mod 26
#
# 20. COMMON MISTAKES TO AVOID
# - Encryption != hashing. Hash has no decrypt.
# - SIGN uses private key; VERIFY uses public key.
# - Hex is representation, NOT encryption.
# - For DES/AES decrypt, use bytes.fromhex(ciphertext_hex).
# - For DES/AES encrypt, output is hex string in this master file.
# - DH/ECDH creates a shared secret; it does not itself encrypt the message.
# - Rabin decryption naturally has 4 possible roots.
# - Multiplicative/Affine decryption needs a modular inverse.
# - Hill key matrix must be invertible mod 26.
# - Current autokey code assumes alphabetic plaintext/ciphertext handling.
#
# 21. EXAM APPROACH
# Step 1: Identify required property.
# Step 2: Identify algorithm.
# Step 3: Write function with exact input/output types.
# Step 4: Keep encrypt/decrypt, sign/verify, hash/verify separate.
# Step 5: Combine functions only after individual pieces work.
#
# 30-SECOND DUMP:
# str <-> bytes = encode/decode
# bytes <-> hex = .hex()/bytes.fromhex()
# DES/AES encrypt = str -> hex str
# DES/AES decrypt = hex str -> str
# hash = str -> hex str
# sign = private -> signature
# verify = public -> boolean
# DH/ECDH = shared secret
# HKDF = shared secret -> AES key
# GCM = encryption + authentication
# Rabin = m^2 mod n -> 4 roots
# JSON = dict <-> file
# RBAC = role -> permission
