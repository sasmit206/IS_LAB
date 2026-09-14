import socket
import hashlib

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("localhost", 4000))
server.listen(1)

print("Server waiting...")

connection, address = server.accept()
print("Connected:", address)

message = connection.recv(1024).decode()

server_hash = hashlib.sha256(message.encode()).hexdigest()

print("Received message:", message)
print("Server SHA-256:", server_hash)

connection.sendall(server_hash.encode())

connection.close()
server.close()