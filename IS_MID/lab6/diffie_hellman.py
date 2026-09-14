'''
Try using the Diffie-Hellman asymmetric encryption standard and verify
the above steps.
'''

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

# Both calculate the same shared secret
alice_secret = pow(B, a, p)
bob_secret = pow(A, b, p)

print("Alice Shared Secret:", alice_secret)
print("Bob Shared Secret:", bob_secret)

if alice_secret == bob_secret:
    print("Key Exchange Successful")
else:
    print("Key Exchange Failed")