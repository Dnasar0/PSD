import socket
import threading
import os
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib


class Peer:
    def __init__(self, host, port):
        self.host = host    # Initialize host
        self.port = port    # Initialize port
        
        self.contactsListFile = "contacts.txt"
        
        self.message = None
        self.hostToMsg = None
        self.portToMsg = None
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP SOCKET
        self.connections = {}  # Store active connections
        self.folder_path = str(self.host) + "_" + str(self.port)
        
        if not os.path.exists(self.folder_path):
            os.mkdir(self.folder_path)
            print(f"Folder '{self.folder_path}' created.")

        self.key = hashlib.sha256(f"{host}:{port}".encode()).digest()  # Generate symmetric key based on host:port combination
        self.iv = os.urandom(16)  # Generate a random IV (Initialization Vector)

    def encrypt_message(self, message):
        """Encrypts the message using AES encryption."""
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)
        encryptor = cipher.encryptor()
        
        # Padding the message
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_message = padder.update(message.encode()) + padder.finalize()
        
        # Encrypt the padded message
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        """Decrypts the encrypted message using AES encryption."""
        backend = default_backend()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=backend)  # Use the correct IV for decryption
        decryptor = cipher.decryptor()
        
        # Decrypt the message
        decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        
        # Unpadding the message
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()
        
        return decrypted_message.decode()

    def connect(self, host, port, name):
        """Connect to a peer."""
        
        try:
            connection = socket.create_connection((host, port))
            self.connections[name] = {
                'socket': connection,
                'address': (host, port)  # Store address properly
            }
            
            print(f"Connected to {name} at {host}:{port}")
            
            threading.Thread(target=self.handle_client, args=(connection, name)).start()
            
            # Cria historico das conversas
            historicConversation = self.folder_path + "/" + str(host) + "_" + str(port) + ".txt"
            
            if not os.path.exists(historicConversation):
                open(historicConversation, "x")
                print(f"File '{historicConversation}' created.")
                
            #Cria lista de contatos
            contactsListPath = self.folder_path + "/" + self.contactsListFile
            
            if not os.path.exists(contactsListPath):
                open(contactsListPath, "a").write(str(host) + "_" + str(port) + "-" + name + "\n")
                
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}")

    def listen(self):
        """Listen for incoming connections."""
        
        self.socket.bind((self.host, self.port))
        print(self.socket)
        
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")

        while True:
            try:
                connection, address = self.socket.accept()
                print(connection)
                
                name = f"{address[0]}:{address[1]}"
                self.connections[name] = {'socket': connection}
                
                threading.Thread(target=self.handle_client, args=(connection, name)).start()
            except OSError as e:
                print(f"Socket error: {e}")
                break

    def send_data(self, name, message):
        """Send encrypted data."""
        try:
            self.message = message
            connection_info = self.connections[name]

            # Generate a new IV for each message
            self.iv = os.urandom(16)

            # Encrypt the message
            encrypted_message = self.encrypt_message(message)

            # Get the length of the encrypted message
            encrypted_message_length = len(encrypted_message).to_bytes(4, 'big')

            # Send the length of the encrypted message, IV, and then the encrypted message
            connection_info['socket'].sendall(encrypted_message_length + self.iv + encrypted_message)

            print(f"Message to {name} delivered successfully.")
            print(self.message)
            open(self.folder_path + "/" + str(self.hostToMsg) + "_" + str(self.portToMsg) + ".txt", "a").write("You- " + self.message + "\n")

        except socket.error as e:
            print(f"Failed to send data. Error: {e}")

    def handle_client(self, connection, name):
        """Handle incoming messages from a client."""
        while True:
            try:
                # Receive the length of the encrypted message
                raw_message_length = connection.recv(4)
                if not raw_message_length:
                    break

                message_length = int.from_bytes(raw_message_length, 'big')

                # Receive the IV (16 bytes)
                iv = connection.recv(16)
                if not iv:
                    break

                # Now receive the encrypted message based on the message_length
                encrypted_message = b""
                while len(encrypted_message) < message_length:
                    chunk = connection.recv(message_length - len(encrypted_message))
                    if not chunk:
                        break
                    encrypted_message += chunk

                if not encrypted_message:
                    break

                # Update the IV for decryption
                self.iv = iv

                # Decrypt the message
                decrypted_message = self.decrypt_message(encrypted_message)

                print(f"\nReceived message: {decrypted_message}")

                # Save the message in the chat history file
                open(self.folder_path + "/" + str(name) + ".txt", "a").write(f"{name}: {decrypted_message}\n")

                # Notify all clients except the sender
                self.notify_all_clients(f"{name}: {decrypted_message}", sender_socket=connection)

            except Exception as e:
                print(f"Error in handle_client: {e}")
                break

        print(f"Connection from {name} closed.")
        del self.connections[name]
        connection.close()

    def notify_all_clients(self, message, sender_socket):
        for client_name, client_info in self.connections.items():
            if client_info['socket'] != sender_socket:
                client_info['socket'].sendall(self.encrypt_message(message))

    def start(self):
        """Start listening for connections."""
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

    def get_connected_clients(self):
        """Return a list of connected clients."""
        return [(name, info['address'][0], info['address'][1]) for name, info in self.connections.items() if 'address' in info]


class P2PChatApp(tk.Tk):
    def __init__(self, peer):
        super().__init__()
        self.peer = peer
        self.title("P2P Chat App")
        self.geometry("400x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Main frame
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Display own IP and Port
        self.ip_label = tk.Label(self.main_frame, text=f"Your IP: {self.peer.host}\nYour Port: {self.peer.port}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        # Initial menu
        self.create_menu()

    def create_menu(self):
        """Create the initial menu with options."""
        self.clear_frame()

        # Display the peer info on top of the screen
        self.ip_label = tk.Label(self.main_frame, text=f"Your IP: {self.peer.host}\nYour Port: {self.peer.port}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        # Create buttons for the menu options
        self.label = tk.Label(self.main_frame, text="Welcome to P2P Chat", font=("Arial", 16))
        self.label.pack(pady=20)

        self.create_connection_button = tk.Button(self.main_frame, text="Create New Connection", command=self.open_new_connection_frame)
        self.create_connection_button.pack(pady=10)

        self.view_clients_button = tk.Button(self.main_frame, text="View Connected Clients", command=self.open_view_clients_frame)
        self.view_clients_button.pack(pady=10)

    def open_new_connection_frame(self):
        """Open the frame to create a new connection."""
        self.clear_frame()

        # Title
        self.title_label = tk.Label(self.main_frame, text="Create New Connection", font=("Arial", 14))
        self.title_label.pack(pady=10)

        # Input for IP address
        self.ip_label = tk.Label(self.main_frame, text="Enter IP address:")
        self.ip_label.pack(pady=5)
        self.ip_entry = tk.Entry(self.main_frame)
        self.ip_entry.pack(pady=5)

        # Input for Port
        self.port_label = tk.Label(self.main_frame, text="Enter Port:")
        self.port_label.pack(pady=5)
        self.port_entry = tk.Entry(self.main_frame)
        self.port_entry.pack(pady=5)

        # Input for Name
        self.name_label = tk.Label(self.main_frame, text="Enter a Name:")
        self.name_label.pack(pady=5)
        self.name_entry = tk.Entry(self.main_frame)
        self.name_entry.pack(pady=5)

        # Submit button
        self.submit_button = tk.Button(self.main_frame, text="Connect", command=self.submit_new_connection)
        self.submit_button.pack(pady=10)

        # Back button
        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack(pady=10)

    def submit_new_connection(self):
        """Submit the new connection details."""
        host = self.ip_entry.get()
        port = int(self.port_entry.get())
        name = self.name_entry.get()

        if host and port and name:
            self.peer.connect(host, port, name)
            messagebox.showinfo("Success", f"Connected to {name} at {host}:{port}")
            self.create_menu()
        else:
            messagebox.showwarning("Error", "Please fill in all fields.")

    def open_view_clients_frame(self):
        """Open the frame to view connected clients."""
        self.clear_frame()

        # Title
        self.title_label = tk.Label(self.main_frame, text="Connected Clients", font=("Arial", 14))
        self.title_label.pack(pady=10)

        # Display the connected clients
        self.clients_listbox = tk.Listbox(self.main_frame)
        self.clients_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        connected_clients = self.peer.get_connected_clients()
        for client_name, host, port in connected_clients:
            self.clients_listbox.insert(tk.END, f"{client_name} - {host}:{port}")

        # Select client to open chat
        self.clients_listbox.bind('<<ListboxSelect>>', self.open_chat_frame)

        # Back button
        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack(pady=10)

    def open_chat_frame(self, event):
        """Open a chat window for the selected client."""
        selection = self.clients_listbox.curselection()
        if selection:
            selected_client = self.clients_listbox.get(selection)
            client_name, client_info = selected_client.split(' - ')
            host, port = client_info.split(':')
            
            self.clear_frame()

            # Title
            self.title_label = tk.Label(self.main_frame, text=f"Chat with {client_name}", font=("Arial", 14))
            self.title_label.pack(pady=10)

            # Chat history display
            self.chat_history_text = scrolledtext.ScrolledText(self.main_frame)
            self.chat_history_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

            # Input field to type new messages
            self.message_entry = tk.Entry(self.main_frame)
            self.message_entry.pack(fill=tk.X, padx=10, pady=5)

            # Send button
            self.send_button = tk.Button(self.main_frame, text="Send", command=lambda: self.send_message(client_name))
            self.send_button.pack(pady=5)

            # Back button
            self.back_button = tk.Button(self.main_frame, text="Back", command=self.open_view_clients_frame)
            self.back_button.pack(pady=10)

            # Load chat history
            self.load_chat_history(host, port)

    def accept_connections(self):
        """Accept incoming connections from clients."""
        while True:
            connection, address = self.server.accept()
            print(f"Connected to {address}")
            
            # Register the client in the connections dictionary
            client_name = f"C{len(self.connections)}"  # or however you assign names
            self.connections[client_name] = {'socket': connection}

            # Start a new thread for the client
            threading.Thread(target=self.handle_client, args=(connection, client_name)).start()


    def send_message(self, client_name):
        """Send a message to the selected client."""
    
        message = self.message_input.get()  # Get message from input box
        if client_name in self.connections:
            self.peer.send_data(client_name, message)
        else:
            print(f"Client {client_name} is not connected.")
        
        message = self.message_entry.get()
        if message:
            self.peer.send_data(client_name, message)
            self.chat_history_text.insert(tk.END, f"You: {message}\n")
            self.message_entry.delete(0, tk.END)

    def load_chat_history(self, host, port):
        """Load and display the chat history for the selected client."""
        file_path = os.path.join(self.peer.folder_path, f"{host}_{port}.txt")
        if os.path.exists(file_path):
            with open(file_path, "r") as file:
                chat_history = file.read()
                self.chat_history_text.insert(tk.END, chat_history)

    def clear_frame(self):
        """Clear the current frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def on_close(self):
        """Handle the closing of the application."""
        self.peer.socket.close()  # Close the socket
        self.destroy()  # Close the tkinter window


if __name__ == "__main__":
    host = input("Enter your IP: ")
    port = int(input("Enter your port: "))

    peer = Peer(host, port)
    app = P2PChatApp(peer)

    peer.start()  # Start listening for connections in a separate thread
    app.mainloop()
