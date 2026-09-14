'''
 Implement the hash function in Python. Your function should start with

an initial hash value of 5381 and for each character in the input string,

multiply the current hash value by 33, add the ASCII value of the

character, and use bitwise operations to ensure thorough mixing of the

bits. Finally, ensure the hash value is kept within a 32-bit range by

applying an appropriate mask.
'''

def custom_hash(s):
    hash_value = 5381

    for ch in s:
        # Multiply by 33 and add ASCII value
        hash_value = hash_value * 33 + ord(ch)

        # Bitwise mixing
        hash_value ^= (hash_value >> 16)

        # Keep only 32 bits
        hash_value &= 0xFFFFFFFF

    return hash_value


# Example
message = input("Enter a string: ")
result = custom_hash(message)

print("Hash value:", result)
print("Hash value (hex):", hex(result))