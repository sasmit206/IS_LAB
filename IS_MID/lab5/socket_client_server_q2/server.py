#/usr/bin/python3 /Users/sasmit/Desktop/IS_MID/lab6/q2/server.py

import socket
import hashlib

# Create a TCP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the server to localhost on port 5000
server.bind(("localhost", 4000))

# Start listening for a client
server.listen(1)

print("Server is waiting for a connection...")

# Accept connection from client
connection, address = server.accept()

print("Connected to:", address)

# Receive data from the client
data = connection.recv(1024)

# Convert bytes back to a string for displaying
print("Received data:", data.decode())

# Calculate SHA-256 hash of the received data
server_hash = hashlib.sha256(data).hexdigest()

print("Hash calculated by server:", server_hash)

# Send the hash back to the client
connection.sendall(server_hash.encode())

# Close the connection
connection.close()
server.close()

print("Server closed.")