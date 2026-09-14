import socket
import hashlib

# Create a TCP socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the server running on localhost:5000
client.connect(("localhost", 4000))

# Take message from the user
message = input("Enter message: ")

# Convert the string into bytes because sockets transmit bytes
data = message.encode()

# Calculate the hash locally BEFORE sending the data
local_hash = hashlib.sha256(data).hexdigest()

# Send the data to the server
client.sendall(data)

# Receive the hash calculated by the server
server_hash = client.recv(1024).decode()

# Display both hashes
print("\nHash calculated by client :", local_hash)
print("Hash received from server :", server_hash)

# Compare the two hashes
if local_hash == server_hash:
    print("\nData integrity verified!")
    print("The data was not changed during transmission.")
else:
    print("\nData integrity check FAILED!")
    print("The data may have been corrupted or tampered with.")

# Close the connection
client.close()