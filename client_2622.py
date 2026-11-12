import socket

HOST = "127.0.0.1"
PORT = 50622

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

print("Connected to server\n")

menu = client.recv(4096).decode()
print(menu)

while True:

    cmd = input("Enter command: ").strip()

    if not cmd:
        continue

    payload = f"LEN:{len(cmd)}\n{cmd}"

    client.send(payload.encode())

    response = client.recv(4096).decode()

    print("Server:", response)

    if cmd.upper() == "EXIT":
        break

client.close()
