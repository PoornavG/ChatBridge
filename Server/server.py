import socket
import threading
import sqlite3
import bcrypt

clients = {}

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        print("Username already exists.")
    conn.close()

def authenticate_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    if result and bcrypt.checkpw(password.encode(), result[0]):
        return True
    return False

def remove_client(client_socket):
    for username, client_info in clients.items():
        if client_info['socket'] == client_socket:
            del clients[username]
            break

def handle_client(client_socket):
    try:
        client_socket.send("Do you have an account? (yes/no):".encode())
        response = client_socket.recv(1024).decode().strip().lower()
        
        if response == "no":
            client_socket.send("Enter a new username:".encode())
            new_username = client_socket.recv(1024).decode()
            client_socket.send("Enter a new password:".encode())
            new_password = client_socket.recv(1024).decode()
            add_user(new_username, new_password)
            client_socket.send("Registration successful. Please log in.".encode())

        client_socket.send("Enter username:".encode())
        username = client_socket.recv(1024).decode()
        client_socket.send("Enter password:".encode())
        password = client_socket.recv(1024).decode()
        
        if authenticate_user(username, password):
            client_socket.send("Authentication successful".encode())
            clients[username] = {'socket': client_socket, 'ip': client_socket.getpeername()[0]}
        else:
            client_socket.send("Authentication failed".encode())
            client_socket.close()
            return

        while True:
            client_socket.send("Enter destination IP:".encode())
            destination_ip = client_socket.recv(1024).decode()
            while True:
                target_socket = None
                for client_info in clients.values():
                    if client_info['ip'] == destination_ip:
                        target_socket = client_info['socket']
                        break

                if target_socket:
                    client_socket.send("Valid IP".encode())
                    break
                else:
                    client_socket.send("Invalid IP".encode())
                    destination_ip = client_socket.recv(1024).decode()

            while True:
                message = client_socket.recv(1024)
                if not message:
                    break
                target_socket.send(message)

    except:
        pass
    finally:
        remove_client(client_socket)
        client_socket.close()

def start_server(ip, port):
    init_db()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ip, port))
    server_socket.listen(5)
    print(f"Server started on {ip}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    server_ip = "0.0.0.0"  # Bind to all available interfaces
    server_port = 49154
    start_server(server_ip, server_port)
