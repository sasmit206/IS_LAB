import socket
import hashlib

# Create TCP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Use port 4000
server.bind(("localhost", 4000))

# Listen for one client
server.listen(1)

print("Server is waiting for a connection...")

# Accept client connection
connection, address = server.accept()

print("Connected to:", address)

# List to store all received chunks
chunks = []

while True:
    # Receive one chunk of data
    data = connection.recv(1024)

    # Client sends an empty message to indicate
    # that all chunks have been sent
    if not data:
        break

    # Store the received chunk
    chunks.append(data)

    print("Received chunk:", data.decode())

# Combine all chunks into one complete message
complete_message = b"".join(chunks)

print("\nReassembled message:")
print(complete_message.decode())

# Calculate SHA-256 hash of the complete message
server_hash = hashlib.sha256(complete_message).hexdigest()

print("Server hash:", server_hash)

# Send the hash back to the client
connection.sendall(server_hash.encode())

# Close connection
connection.close()
server.close()

print("Server closed.")