'''
Try using the Elgammal, Schnor asymmetric encryption standard and
verify the above steps.
'''


import hashlib
import math

# Public parameters
p = 467
g = 2

# Private key
x = 127

# Public key
y = pow(g, x, p)

print("Public Key:", (p, g, y))
print("Private Key:", x)

message = input("Enter message: ")

# Hash the message
H = int(hashlib.sha256(message.encode()).hexdigest(), 16)

# Random value used only for this signature
k = 213

# k must be relatively prime to p - 1
while math.gcd(k, p - 1) != 1:
    k += 1

# Generate signature (r, s)
r = pow(g, k, p)
k_inverse = pow(k, -1, p - 1)
s = ((H - x * r) * k_inverse) % (p - 1)

print("\nSignature:")
print("r =", r)
print("s =", s)

# Verify using the public key
left = pow(g, H, p)
right = (pow(y, r, p) * pow(r, s, p)) % p

print("\nVerification")
print("Left :", left)
print("Right:", right)

if left == right:
    print("Digital Signature VALID")
else:
    print("Digital Signature INVALID")