'''
Design a Python-based experiment to analyze the performance of MD5,
SHA-1, and SHA-256 hashing techniques in terms of computation time
and collision resistance. Generate a dataset of random strings ranging
from 50 to 100 strings, compute the hash values using each hashing
technique, and measure the time taken for hash computation. Implement
collision detection algorithms to identify any collisions within the
hashed dataset.
'''


import hashlib
import random
import string
import time


# ---------------------------------------------------------
# 1. Generate random strings
# ---------------------------------------------------------

def generate_random_strings(count=100, length=20):
    strings = []

    for _ in range(count):
        # Generate a random string containing letters and digits
        random_string = ''.join(
            random.choices(string.ascii_letters + string.digits, k=length)
        )

        strings.append(random_string)

    return strings


# ---------------------------------------------------------
# 2. Calculate hashes and measure computation time
# ---------------------------------------------------------

def test_hash_algorithm(data, algorithm):
    hashes = []
    
    # Start the timer
    start_time = time.perf_counter()

    for text in data:
        # Convert string to bytes because hashlib works with bytes
        text_bytes = text.encode()

        if algorithm == "MD5":
            hash_value = hashlib.md5(text_bytes).hexdigest()

        elif algorithm == "SHA-1":
            hash_value = hashlib.sha1(text_bytes).hexdigest()

        elif algorithm == "SHA-256":
            hash_value = hashlib.sha256(text_bytes).hexdigest()

        hashes.append(hash_value)

    # Stop the timer
    end_time = time.perf_counter()

    # Total time taken
    execution_time = end_time - start_time

    return hashes, execution_time


# ---------------------------------------------------------
# 3. Detect collisions
# ---------------------------------------------------------

def detect_collisions(data, hashes):
    seen = {}
    collisions = []

    for original_string, hash_value in zip(data, hashes):

        # If this hash has already appeared,
        # two different inputs have the same hash
        if hash_value in seen:

            previous_string = seen[hash_value]

            if previous_string != original_string:
                collisions.append(
                    (previous_string, original_string, hash_value)
                )

        else:
            seen[hash_value] = original_string

    return collisions


# ---------------------------------------------------------
# 4. Main experiment
# ---------------------------------------------------------

data = generate_random_strings(100, 20)

algorithms = ["MD5", "SHA-1", "SHA-256"]

print("=" * 60)
print("HASH PERFORMANCE AND COLLISION EXPERIMENT")
print("=" * 60)

print("\nNumber of input strings:", len(data))
print("Length of each string:", len(data[0]))

for algorithm in algorithms:

    print("\n" + "-" * 60)
    print(algorithm)
    print("-" * 60)

    # Calculate hashes and measure time
    hashes, execution_time = test_hash_algorithm(
        data, algorithm
    )

    # Detect collisions
    collisions = detect_collisions(data, hashes)

    print("Time taken:", execution_time, "seconds")
    print("Number of collisions:", len(collisions))

    # Display collisions if any were found
    if collisions:

        print("\nCollisions found:")

        for collision in collisions:
            print("Input 1:", collision[0])
            print("Input 2:", collision[1])
            print("Hash:", collision[2])

    else:
        print("No collisions detected.")