import socket
import threading
import tkinter as tk
from tkinter import simpledialog, scrolledtext, messagebox

class ClientApp:
    def __init__(self, window):
        self.window = window
        self.window.title("Client Application")

        self.server_ip = tk.StringVar()
        self.server_ip_entry = tk.Entry(window, textvariable=self.server_ip)
        self.server_ip_entry.pack(padx=10, pady=10, fill=tk.X)
        self.server_ip_entry.insert(0, "Enter server IP")

        self.connect_button = tk.Button(window, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.pack(padx=10, pady=10)

        self.text_area = scrolledtext.ScrolledText(window, wrap=tk.WORD, state=tk.DISABLED)
        self.text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.message_frame = tk.Frame(window)
        self.message_frame.pack(padx=10, pady=10, fill=tk.X)

        self.message_entry = tk.Entry(self.message_frame)
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        self.send_button = tk.Button(self.message_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        self.client_socket = None

    def connect_to_server(self):
        ip = self.server_ip.get()
        port = 49154
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((ip, port))
            messagebox.showinfo("Connection", f"Connected to server at {ip}:{port}")

            if not self.authenticate():
                messagebox.showerror("Authentication", "Authentication failed. Closing connection.")
                self.client_socket.close()
                return

            while True:
                destination_ip = simpledialog.askstring("Destination", "Enter destination IP:")
                self.client_socket.send(destination_ip.encode())
                response = self.client_socket.recv(1024).decode()
                if response == "Valid IP":
                    break
                else:
                    messagebox.showwarning("Invalid IP", "No client with the given IP address. Please enter a different one.")

            threading.Thread(target=self.receive_messages).start()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            self.client_socket.close()

    def authenticate(self):
        username = simpledialog.askstring("Login", "Enter username:")
        self.client_socket.send(username.encode())
        password = simpledialog.askstring("Login", "Enter password:", show='*')
        self.client_socket.send(password.encode())

        response = self.client_socket.recv(1024).decode()
        messagebox.showinfo("Server Response", response)
        return "successful" in response

    def receive_messages(self):
        while True:
            try:
                response = self.client_socket.recv(1024).decode()
                if not response:
                    break
                self.text_area.config(state=tk.NORMAL)
                self.text_area.insert(tk.END, f"\nReceived from other client: {response}")
                self.text_area.config(state=tk.DISABLED)
                self.text_area.yview(tk.END)
            except:
                break

    def send_message(self):
        message = self.message_entry.get()
        self.client_socket.send(message.encode())
        self.message_entry.delete(0, tk.END)

    def on_closing(self):
        if self.client_socket:
            self.client_socket.close()
        self.window.destroy()

if __name__ == "__main__":
    window = tk.Tk()
    app = ClientApp(window)
    window.protocol("WM_DELETE_WINDOW", app.on_closing)
    window.mainloop()
