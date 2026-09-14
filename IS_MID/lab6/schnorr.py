'''
Try using the Elgammal, Schnor asymmetric encryption standard and
verify the above steps.
'''


import hashlib

# Public parameters
p = 23
q = 11
g = 2

# Private key
x = 7

# Public key
y = pow(g, -x, p)

message = input("Enter message: ")

# Random value used to create the commitment
k = 3

# Commitment
r = pow(g, k, p)

# Challenge generated from message and commitment
e = int(
    hashlib.sha256((message + str(r)).encode()).hexdigest(),
    16
) % q

# Signature
s = (k + x * e) % q

print("\nPublic Key:", y)
print("Signature:", (s, e))

# Reconstruct commitment using the public key
r_new = (pow(g, s, p) * pow(y, e, p)) % p

# Generate the challenge again
e_new = int(
    hashlib.sha256((message + str(r_new)).encode()).hexdigest(),
    16
) % q

print("\nVerification")
print("Original e :", e)
print("New e      :", e_new)

if e == e_new:
    print("Digital Signature VALID")
else:
    print("Digital Signature INVALID")