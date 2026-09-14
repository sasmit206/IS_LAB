import socket
import hashlib

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 4000))

message = input("Enter message: ")

# Calculate hash before sending
local_hash = hashlib.sha256(message.encode()).hexdigest()

client.sendall(message.encode())

server_hash = client.recv(1024).decode()

print("\nClient SHA-256 :", local_hash)
print("Server SHA-256 :", server_hash)

if local_hash == server_hash:
    print("Data integrity verified")
else:
    print("Data integrity check FAILED")

client.close()