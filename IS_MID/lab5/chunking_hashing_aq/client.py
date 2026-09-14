'''
Write server and client scripts where the client sends a message in multiple parts to
the server, the server reassembles the message, computes the hash of the reassembled
message, and sends this hash back to the client. The client then verifies the integrity
of the message by comparing the received hash with the locally computed hash of the
original message.
'''

import socket
import hashlib

# Create TCP socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to server on port 4000
client.connect(("localhost", 4000))

# Original message
message = input("Enter message: ")

# Convert message to bytes
data = message.encode()

# Calculate hash of the ORIGINAL message
# This will be used later for comparison
local_hash = hashlib.sha256(data).hexdigest()

# Decide how large each chunk should be
chunk_size = 5

# Send the message in multiple parts
for i in range(0, len(data), chunk_size):

    # Extract a chunk of the message
    chunk = data[i:i + chunk_size]

    # Send this chunk to the server
    client.sendall(chunk)

    print("Sent chunk:", chunk.decode())

# Tell server that all chunks have been sent
# Shutting down only the sending side allows the server's
# recv() to eventually return b'' and know transmission is finished.
client.shutdown(socket.SHUT_WR)

# Receive the hash calculated by the server
server_hash = client.recv(1024).decode()

print("\nHash calculated by client :", local_hash)
print("Hash calculated by server :", server_hash)

# Compare both hashes
if local_hash == server_hash:
    print("\nData integrity verified!")
    print("The message was received correctly.")
else:
    print("\nData integrity check FAILED!")
    print("The message may have been corrupted or tampered with.")

# Close connection
client.close()