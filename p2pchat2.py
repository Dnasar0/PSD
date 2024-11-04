import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
import secrets

# Import cryptographic primitives for encryption and key management
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # For ECDH key exchange
from cryptography.hazmat.primitives import serialization  # For key serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption

# Import Firebase Admin SDK modules for database interaction
import firebase_admin
from firebase_admin import credentials, db

# Initialize Firebase Admin SDK with the credentials file
cred = credentials.Certificate("psdproject-6e38f-firebase-adminsdk-icq10-3708af2f3d.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://psdproject-6e38f-default-rtdb.europe-west1.firebasedatabase.app/'
})

# Directories to store keys and peers list
KEYS_DIR = "keys"
PEERS_DIR = "peersList"

# Create directories if they do not already exist
for directory in [KEYS_DIR, PEERS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Function to derive an AES key from the shared ECDH key
def derive_aes_key(shared_key):
    # Use SHA-256 hash function to derive a 256-bit AES key
    aes_key = hashlib.sha256(shared_key).digest()
    return aes_key

# Function to sanitize strings for Firebase paths by replacing invalid characters
def sanitize_for_firebase_path(s):
    # Replace invalid characters in Firebase paths with underscores
    return s.replace('.', '_').replace('$', '_').replace('#', '_').replace('[', '_').replace(']', '_').replace('/', '_')

# Class representing a connected Peer or Group
class ConnectionEntity:
    def __init__(self, ip, port, connection, public_key, aes_key, is_group=False, group_name=None):
        self.ip = ip  # IP address of the peer
        self.port = port  # Port number of the peer
        self.connection = connection  # Socket connection object
        self.public_key = public_key  # ECDH public key of the peer/group
        self.aes_key = aes_key  # AES key for secure communication
        self.chat_window = None  # Chat window associated with the peer/group
        self.chat_text = None  # Text widget in the chat window
        self.is_group = is_group  # Flag to indicate if it's a group
        self.group_name = group_name  # Group name, if it's a group

# Main P2P Chat Application class
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host  # Local IP address
        self.port = port  # Local port number
        self.peers = {}  # Dictionary to store connected peers and groups
        self.server_socket = None  # Server socket for listening

        # Generate ECDH key pair for secure communication
        self.private_key, self.public_key = self.generate_ecdh_key_pair()
        # Serialize the public key to bytes for transmission
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Initialize the GUI using Tkinter
        self.root = tk.Tk()
        self.root.title(f"P2P Chat Application: {host}:{port}")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)

        self.current_frame = None  # Current frame in the GUI
        self.setup_main_menu()  # Set up the main menu

        # Bind the window close event to save peers before exiting
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Start the server in a new thread to accept incoming connections
        threading.Thread(target=self.start_server, daemon=True).start()

        # Load peers from file to restore previous connections
        self.load_peers_from_file()

    def get_peers_filename(self):
        """
        Generates a unique filename for storing peers based on host and port, inside the peersList folder.
        """
        sanitized_host = sanitize_for_firebase_path(self.host)
        filename = f"peers_{sanitized_host}_{self.port}.json"
        return os.path.join(PEERS_DIR, filename)

    def on_close(self):
        """
        Handles the window close event to save peers before exiting.
        """
        self.save_peers_to_file()
        self.root.destroy()

    def save_peers_to_file(self):
        """
        Saves the list of connected peers and groups to a JSON file inside the peersList folder.
        """
        peers_list = []
        for key, entity in self.peers.items():
            if entity.is_group:
                peers_list.append({
                    'is_group': True,
                    'group_name': entity.group_name
                })
            else:
                peers_list.append({
                    'is_group': False,
                    'ip': entity.ip,
                    'port': entity.port
                })
        filename = self.get_peers_filename()
        with open(filename, 'w') as f:
            json.dump(peers_list, f)

    def load_peers_from_file(self):
        """
        Loads the list of connected peers and groups from a JSON file inside the peersList folder.
        """
        filename = self.get_peers_filename()
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                peers_list = json.load(f)
            for peer_info in peers_list:
                if peer_info['is_group']:
                    group_name = peer_info['group_name']
                    if group_name not in self.peers:
                        self.connect_to_group(group_name)
                else:
                    ip = peer_info['ip']
                    port = peer_info['port']
                    # Attempt to connect to peer if not already connected
                    if (ip, port) not in self.peers:
                        threading.Thread(target=self.connect_to_peer, args=(ip, port), daemon=True).start()
        else:
            print("No previous peers to load.")

    def generate_ecdh_key_pair(self):
        """
        Generates an ECDH key pair for secure communication.
        """
        # Generate a private key using the SECP256R1 curve
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        # Derive the corresponding public key
        public_key = private_key.public_key()
        return private_key, public_key

    def setup_main_menu(self):
        """
        Sets up the main menu of the GUI with options to connect, view peers, search messages, and view recommendations.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        # Display the user's IP and port
        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        # Button to connect to a new peer or group
        self.connect_button = tk.Button(self.current_frame, text="Connect", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        # Button to view the list of connected peers and groups
        self.list_button = tk.Button(self.current_frame, text="Peers/Groups List", command=self.show_peer_list)
        self.list_button.pack(pady=10)

        # Button to search messages
        self.search_button = tk.Button(self.current_frame, text="Search Messages", command=self.search_messages)
        self.search_button.pack(pady=10)

        # Button to view personalized recommendations
        self.recommendations_button = tk.Button(self.current_frame, text="View Recommendations", command=self.show_recommendations)
        self.recommendations_button.pack(pady=10)

    def show_connection_inputs(self):
        """
        Displays the input fields to connect to a new peer or group.
        """
        self.clear_frame()

        # Variable to store the selected connection type (peer or group)
        connection_type_var = tk.StringVar(value="peer")
        tk.Label(self.current_frame, text="Connection Type:").pack(pady=5)
        # Radio buttons to select connection type
        tk.Radiobutton(self.current_frame, text="Peer", variable=connection_type_var, value="peer", command=self.update_connection_inputs).pack()
        tk.Radiobutton(self.current_frame, text="Group", variable=connection_type_var, value="group", command=self.update_connection_inputs).pack()

        self.connection_type_var = connection_type_var

        # Create frames for peer inputs and group inputs
        self.peer_inputs_frame = tk.Frame(self.current_frame)
        self.group_inputs_frame = tk.Frame(self.current_frame)

        # Peer inputs
        tk.Label(self.peer_inputs_frame, text="IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.peer_inputs_frame, text="Port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_port_entry.pack(pady=5)

        # Group inputs
        tk.Label(self.group_inputs_frame, text="Group Name:").pack(pady=5)
        self.group_name_entry = tk.Entry(self.group_inputs_frame)
        self.group_name_entry.pack(pady=5)

        # Initially show peer inputs
        self.peer_inputs_frame.pack()

        # Button to initiate connection
        self.connect_peer_button = tk.Button(
            self.current_frame,
            text="Connect",
            command=lambda: self.connect_to_entity(connection_type_var.get())
        )
        self.connect_peer_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def update_connection_inputs(self):
        """
        Updates the input fields shown based on the connection type selected (peer or group).
        """
        connection_type = self.connection_type_var.get()
        if connection_type == 'peer':
            # Show peer inputs and hide group inputs
            self.group_inputs_frame.pack_forget()
            self.peer_inputs_frame.pack()
        elif connection_type == 'group':
            # Show group inputs and hide peer inputs
            self.peer_inputs_frame.pack_forget()
            self.group_inputs_frame.pack()

    def clear_frame(self):
        """
        Clears the current frame to load new widgets.
        """
        for widget in self.current_frame.winfo_children():
            widget.destroy()

    def start_server(self):
        """
        Starts the server to accept connections from peers.
        """
        try:
            # Create a socket and bind it to the host and port
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"Error starting server: {e}")
            messagebox.showerror("Error", f"Unable to start server: {e}")
            sys.exit(1)

        # Continuously accept incoming connections
        while True:
            try:
                conn, addr = self.server_socket.accept()
                peer_ip, _ = addr  # Get the IP address of the connecting peer

                # Start a new thread to handle the new connection
                threading.Thread(
                    target=self.handle_new_connection,
                    args=(conn, peer_ip),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def handle_new_connection(self, conn, peer_ip):
        """
        Processes new connections received from peers.
        """
        try:
            # Exchange public keys with the peer for ECDH key exchange
            peer_public_key_bytes = self.receive_all(conn)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
            print("Received peer's public key")

            # Send own public key to the peer
            conn.sendall(self.public_key_bytes)
            print("Sent own public key")

            # Generate shared secret using ECDH and derive AES key
            shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
            session_aes_key = derive_aes_key(shared_key)

            # Receive connection type and listening port from the peer
            msg_length_bytes = conn.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed by peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_info = self.receive_exact(conn, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)

            # Send own connection type and listening port to the peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            msg_length = len(encrypted_info)
            conn.sendall(msg_length.to_bytes(4, byteorder='big'))
            conn.sendall(encrypted_info)

            # Determine if the connection is to a group or a peer
            is_group = (connection_type == 'group')

            # Create a ConnectionEntity to represent the connection
            entity = ConnectionEntity(peer_ip, peer_listening_port, conn, peer_public_key, session_aes_key, is_group)
            self.peers[(peer_ip, peer_listening_port)] = entity  # Use tuple as key
            print(f"Connected: {peer_ip}:{peer_listening_port} as {'Group' if is_group else 'Peer'}")

            # Start a thread to receive messages from the peer
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()

        except Exception as e:
            print(f"Error establishing connection with {peer_ip}: {e}")
            conn.close()

    def connect_to_entity(self, connection_type):
        """
        Connects to a remote peer or group using user-provided IP and port or group name.
        """
        if connection_type == 'peer':
            # Get IP and port from input fields
            peer_ip = self.peer_ip_entry.get()
            peer_port = self.peer_port_entry.get()

            # Input validation for IP and port
            if not self.validate_ip(peer_ip) or not peer_port.isdigit():
                messagebox.showerror("Error", "Invalid IP or port!")
                return

            peer_port = int(peer_port)

            if (peer_ip, peer_port) in self.peers:
                messagebox.showinfo("Info", f"Already connected to {peer_ip}:{peer_port}")
                return

            # Start a thread to connect to the peer and update UI
            threading.Thread(target=self.connect_to_peer_ui, args=(peer_ip, peer_port), daemon=True).start()

        elif connection_type == 'group':
            # Get group name from input field
            group_name = self.group_name_entry.get()
            if not group_name:
                messagebox.showerror("Error", "Group name cannot be empty!")
                return

            self.connect_to_group(group_name)

    def connect_to_group(self, group_name):
        """
        Connects to a group chat by name.
        """
        if group_name not in self.peers:
            # Create a ConnectionEntity for the group
            entity = ConnectionEntity(None, None, None, None, None, is_group=True, group_name=group_name)
            self.peers[group_name] = entity
            # Start a thread to receive messages from the group
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            messagebox.showinfo("Connected to Group", f"Connected to group '{group_name}'")
            self.setup_main_menu()
        else:
            messagebox.showinfo("Info", f"Already connected to group '{group_name}'")

    def connect_to_peer_ui(self, peer_ip, peer_port):
        """
        Connects to a peer and updates the UI accordingly.
        """
        try:
            self.connect_to_peer(peer_ip, peer_port)
            # Inform the user upon successful connection
            self.root.after(0, lambda: messagebox.showinfo("Connection Established", f"Connected to {peer_ip}:{peer_port} as Peer"))
            self.root.after(0, self.setup_main_menu)
        except Exception as e:
            # Show an error message if the connection fails
            self.root.after(0, lambda: messagebox.showerror("Connection Error", f"Could not connect to {peer_ip}:{peer_port}\nError: {e}"))

    def connect_to_peer(self, peer_ip, peer_port):
        """
        Connects to a peer using the provided IP and port.
        """
        try:
            # Create a socket and connect to the peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Send own public key to the peer
            sock.sendall(self.public_key_bytes)
            print("Sent own public key")

            # Receive peer's public key
            peer_public_key_bytes = self.receive_all(sock)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
            print("Received peer's public key")

            # Generate shared secret using ECDH and derive AES key
            shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
            session_aes_key = derive_aes_key(shared_key)

            # Send own connection type and listening port to the peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            msg_length = len(encrypted_info)
            sock.sendall(msg_length.to_bytes(4, byteorder='big'))
            sock.sendall(encrypted_info)

            # Receive peer's connection type and listening port
            msg_length_bytes = sock.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed by peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_info = self.receive_exact(sock, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            peer_connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)

            # Determine if the peer is a group or a peer
            is_group = (peer_connection_type == 'group')

            # Create a ConnectionEntity to represent the connection
            entity = ConnectionEntity(peer_ip, peer_listening_port, sock, peer_public_key, session_aes_key, is_group)
            self.peers[(peer_ip, peer_listening_port)] = entity  # Use tuple as key
            # Start a thread to receive messages from the peer
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            print(f"Connected to {peer_ip}:{peer_port} as {'Group' if is_group else 'Peer'}")

        except Exception as e:
            print(f"Could not connect to {peer_ip}:{peer_port}\nError: {e}")
            # Remove the peer from peers list if connection fails
            if (peer_ip, peer_port) in self.peers:
                del self.peers[(peer_ip, peer_port)]
            raise

    def validate_ip(self, ip):
        """
        Validates if the provided IP is valid.
        """
        parts = ip.split(".")
        # Check if IP consists of four parts and each part is between 0 and 255
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def receive_all(self, conn):
        """
        Receives all data from the connection until there's no more.
        """
        data = b''
        while True:
            part = conn.recv(4096)
            if not part:
                break
            data += part
            if len(part) < 4096:
                break
        return data

    def receive_exact(self, conn, num_bytes):
        """
        Receives exactly the specified number of bytes from the connection.
        """
        data = b''
        while len(data) < num_bytes:
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                raise Exception("Connection closed before receiving all data!")
            data += packet
        return data

    def receive_messages(self, entity):
        """
        Receives messages from the peer or group and updates the chat interface.
        """
        if entity.is_group:
            # For groups, listen to messages from the cloud database
            threading.Thread(target=self.listen_to_group_messages, args=(entity,), daemon=True).start()
        else:
            while True:
                try:
                    # Receive message length (4 bytes)
                    msg_length_bytes = entity.connection.recv(4)
                    if not msg_length_bytes:
                        raise Exception("Connection closed by peer!")
                    msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                    # Receive the encrypted message
                    encrypted_message = self.receive_exact(entity.connection, msg_length)
                    # Decrypt the message using AES key
                    message = self.decrypt_message(encrypted_message, entity.aes_key)
                    print(f"Message received from {entity.ip}:{entity.port}: {message}")

                    # Update the chat window if it's open
                    if entity.chat_window:
                        self.update_chat_window(entity, f"{entity.ip}:{entity.port}: {message}")
                    # Save the message to the cloud database
                    self.save_chat_to_cloud(entity, f"{entity.ip}:{entity.port}", message)

                except Exception as e:
                    print(f"Connection to {entity.ip}:{entity.port} closed: {e}")
                    entity.connection.close()
                    # Remove the peer from peers list if connection is closed
                    if (entity.ip, entity.port) in self.peers:
                        del self.peers[(entity.ip, entity.port)]  # Use tuple as key
                    break

    def listen_to_group_messages(self, group_entity):
        """
        Listens to messages from the group in the cloud database.
        """
        group_id = sanitize_for_firebase_path(group_entity.group_name)
        group_ref = db.reference(f"groups/{group_id}/messages")

        def listener(event):
            # Event listener for new messages in the group
            if event.data and event.event_type == 'put':
                # Check if the event is for a new message
                if event.path != '/':
                    message_data = event.data
                    # Handle both dict and string formats
                    if isinstance(message_data, dict):
                        sender = message_data.get('sender', '')
                        message = message_data.get('message', '')
                    else:
                        sender = ''
                        message = message_data
                    if sender != f"{self.host}:{self.port}":
                        if group_entity.chat_window:
                            if sender:
                                display_message = f"{sender}: {message}"
                            else:
                                display_message = message
                            self.update_chat_window(group_entity, display_message)

        # Start listening to the group messages
        group_ref.listen(listener)

    def show_peer_list(self):
        """
        Displays the list of connected peers and groups.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Connected Peers and Groups")
        label.pack(pady=10)

        if not self.peers:
            label = tk.Label(self.current_frame, text="No peers or groups connected")
            label.pack(pady=10)
        else:
            # Listbox to display peers and groups
            listbox = tk.Listbox(self.current_frame)
            for idx, key in enumerate(self.peers):
                entity = self.peers[key]
                if entity.is_group:
                    listbox.insert(idx, f"Group - {entity.group_name}")
                else:
                    listbox.insert(idx, f"Peer - {entity.ip}:{entity.port}")
            listbox.pack(pady=10)

            def open_chat():
                # Open chat window with the selected peer or group
                selected_idx = listbox.curselection()
                if selected_idx:
                    selected_item = listbox.get(selected_idx[0])
                    if selected_item.startswith('Group - '):
                        group_name = selected_item[len('Group - '):]
                        selected_entity = self.peers[group_name]
                    elif selected_item.startswith('Peer - '):
                        addr = selected_item[len('Peer - '):]
                        selected_ip, selected_port = addr.split(':')
                        selected_port = int(selected_port)
                        selected_entity = self.peers.get((selected_ip, selected_port))
                        if not selected_entity:
                            messagebox.showerror("Error", f"Peer {selected_ip}:{selected_port} is not connected.")
                            return
                    self.open_chat_window(selected_entity)

            # Button to open chat with the selected entity
            open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, entity):
        """
        Opens a chat window for communication with the peer or group.
        """
        if entity.chat_window:
            # Check if the window is already open
            try:
                entity.chat_window.winfo_exists()
                entity.chat_window.lift()
                return
            except tk.TclError:
                # The window no longer exists; reset references
                entity.chat_window = None
                entity.chat_text = None

        # Create a new window for the chat
        chat_window = tk.Toplevel(self.root)
        if entity.is_group:
            title = f"Chat with Group '{entity.group_name}'"
        else:
            title = f"Chat with Peer {entity.ip}:{entity.port}"
        chat_window.title(title)
        chat_window.geometry("500x500")

        # Main frame for the chat window
        main_frame = tk.Frame(chat_window)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Chat history text area
        chat_text = tk.Text(main_frame, height=20, width=60)
        chat_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        chat_text.config(state=tk.DISABLED)

        # Load chat history from the cloud database
        self.load_chat_from_cloud(entity, chat_text)

        # Frame for message entry and buttons
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Back button to close the chat window
        back_button = tk.Button(bottom_frame, text="Back", command=lambda: self.close_chat_window(entity))
        back_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Message entry field
        message_var = tk.StringVar()
        message_entry = tk.Entry(bottom_frame, textvariable=message_var)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0), pady=5)

        # Send button to send messages
        send_button = tk.Button(bottom_frame, text="Send", command=lambda: self.send_message(entity, message_var))
        send_button.pack(side=tk.RIGHT, padx=(0, 5), pady=5)

        # Bind Enter key to send message
        message_entry.bind('<Return>', lambda event: self.send_message(entity, message_var))

        # Store references to the chat window and text area
        entity.chat_window = chat_window
        entity.chat_text = chat_text

        def on_close():
            # Handle chat window close event
            self.close_chat_window(entity)

        chat_window.protocol("WM_DELETE_WINDOW", on_close)

    def close_chat_window(self, entity):
        """
        Closes the chat window and cleans up references.
        """
        if entity.chat_window:
            entity.chat_window.destroy()
            entity.chat_window = None
            entity.chat_text = None

    def send_message(self, entity, message_var):
        """
        Sends a message to the peer or group using AES encryption.
        """
        message = message_var.get()
        if message:
            message_var.set("")  # Clear the input field

            try:
                if entity.is_group:
                    # For groups, send the message to the cloud database
                    self.save_chat_to_cloud(entity, f"{self.host}:{self.port}", message)
                else:
                    # For peers, send the message directly over the socket
                    encrypted_message = self.encrypt_message(message, entity.aes_key)
                    msg_length = len(encrypted_message)
                    entity.connection.sendall(msg_length.to_bytes(4, byteorder='big'))
                    entity.connection.sendall(encrypted_message)
                    print("Sent message")
                    self.save_chat_to_cloud(entity, f"You", message)

                # Update the chat window with the sent message
                self.update_chat_window(entity, f"You: {message}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")

    def update_chat_window(self, entity, message):
        """
        Updates the chat window with new messages.
        """
        if entity.chat_window:
            text_area = entity.chat_text
            if text_area:
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, message + '\n')
                text_area.config(state=tk.DISABLED)
                text_area.see(tk.END)

    def save_chat_to_cloud(self, entity, sender, message):
        """
        Saves the conversation to the cloud database.
        """
        if entity.is_group:
            # Save messages under the group's reference in Firebase
            group_id = sanitize_for_firebase_path(entity.group_name)
            group_ref = db.reference(f"groups/{group_id}/messages")
            group_ref.push({'sender': sender, 'message': message})
        else:
            # Save messages under the chat's reference in Firebase
            chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_ref = db.reference(f"chats/{chat_id}")
            chat_ref.push({'sender': sender, 'message': message})

        # Simulate recommendation system by analyzing messages
        self.analyze_message_for_recommendations(message)

    def load_chat_from_cloud(self, entity, text_area):
        """
        Loads the conversation history from the cloud database.
        """
        if entity.is_group:
            # Load messages from the group's reference in Firebase
            group_id = sanitize_for_firebase_path(entity.group_name)
            group_ref = db.reference(f"groups/{group_id}/messages")
            messages = group_ref.get()
            if messages:
                for key in messages:
                    message_data = messages[key]
                    # Handle both dict and string formats
                    if isinstance(message_data, dict):
                        sender = message_data.get('sender', '')
                        message = message_data.get('message', '')
                    else:
                        sender = ''
                        message = message_data
                    if sender:
                        display_message = f"{sender}: {message}"
                    else:
                        display_message = message
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, display_message + '\n')
                    text_area.config(state=tk.DISABLED)
        else:
            # Load messages from the chat's reference in Firebase
            chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_ref = db.reference(f"chats/{chat_id}")
            messages = chat_ref.get()
            if messages:
                for key in messages:
                    message_data = messages[key]
                    # Handle both dict and string formats
                    if isinstance(message_data, dict):
                        sender = message_data.get('sender', '')
                        message = message_data.get('message', '')
                    else:
                        sender = ''
                        message = message_data
                    if sender:
                        display_message = f"{sender}: {message}"
                    else:
                        display_message = message
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, display_message + '\n')
                    text_area.config(state=tk.DISABLED)

    def encrypt_message(self, message, aes_key):
        """
        Encrypts the message using AES in GCM mode.
        """
        nonce = secrets.token_bytes(12)  # Generate a random nonce
        # Create an AES-GCM encryptor object
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
        # Encrypt the message
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        # Return the concatenation of nonce, ciphertext, and tag
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, encrypted_message, aes_key):
        """
        Decrypts the message using AES in GCM mode.
        """
        nonce = encrypted_message[:12]  # Extract the nonce
        tag = encrypted_message[-16:]  # Extract the tag
        ciphertext = encrypted_message[12:-16]  # Extract the ciphertext
        # Create an AES-GCM decryptor object
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def search_messages(self):
        """
        Allows users to search conversations using keywords without compromising message security.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Search Messages").pack(pady=10)

        # Entry field for keywords
        keyword_var = tk.StringVar()
        keyword_entry = tk.Entry(self.current_frame, textvariable=keyword_var, width=30)
        keyword_entry.pack(pady=5)

        # Text area to display search results
        result_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        result_text.pack(pady=10)

        def perform_search():
            # Perform the search based on input keywords
            keywords = keyword_var.get().strip()
            if keywords:
                keyword_list = keywords.split()
                result_text.config(state=tk.NORMAL)
                result_text.delete('1.0', tk.END)
                results = self.perform_privacy_preserving_search(keyword_list)
                if results:
                    for res in results:
                        result_text.insert(tk.END, res + '\n')
                else:
                    result_text.insert(tk.END, "No matching messages found.")
                result_text.config(state=tk.DISABLED)

        # Button to initiate search
        search_button = tk.Button(self.current_frame, text="Search", command=perform_search)
        search_button.pack(pady=5)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def perform_privacy_preserving_search(self, keywords):
        """
        Searches all connected peers/groups for messages containing the keywords.
        """
        results = []

        # Get connected peers and groups
        connected_entities = self.peers

        # For each connected entity, retrieve the chat messages
        for key, entity in connected_entities.items():
            if entity.is_group:
                # Search messages in the group
                group_id = sanitize_for_firebase_path(entity.group_name)
                group_ref = db.reference(f"groups/{group_id}/messages")
                messages = group_ref.get()
                if messages:
                    line_number = 0
                    for msg_key in messages:
                        line_number += 1
                        message_data = messages[msg_key]
                        # Handle both dict and string formats
                        if isinstance(message_data, dict):
                            message = message_data.get('message', '')
                        else:
                            message = message_data
                        # Check if any keyword is in the message
                        if any(keyword.lower() in message.lower() for keyword in keywords):
                            results.append(f"Group '{entity.group_name}', Line {line_number}: {message}")
            else:
                # Search messages in the peer chat
                chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
                chat_ref = db.reference(f"chats/{chat_id}")
                messages = chat_ref.get()
                if messages:
                    line_number = 0
                    for msg_key in messages:
                        line_number += 1
                        message_data = messages[msg_key]
                        # Handle both dict and string formats
                        if isinstance(message_data, dict):
                            message = message_data.get('message', '')
                        else:
                            message = message_data
                        if any(keyword.lower() in message.lower() for keyword in keywords):
                            results.append(f"Peer {entity.ip}:{entity.port}, Line {line_number}: {message}")

        return results

    def analyze_message_for_recommendations(self, message):
        """
        Analyzes messages to generate recommendations.
        """
        # Simple keyword-based recommendation simulation
        ads = {
            'sports': 'Check out the latest sports gear!',
            'music': 'Discover new music albums!',
            'travel': 'Plan your next vacation with us!',
            'technology': 'Upgrade your gadgets with the newest tech!',
            'food': 'Explore delicious recipes and restaurants!'
        }

        for keyword, ad in ads.items():
            if keyword in message.lower():
                # Store the recommendation in the database
                user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
                rec_ref = db.reference(f"recommendations/{user_id}")
                rec_ref.set({'ad': ad})

    def show_recommendations(self):
        """
        Displays personalized recommendations to the user.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Your Recommendations").pack(pady=10)

        # Text area to display recommendations
        recommendations_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        recommendations_text.pack(pady=10)

        # Retrieve recommendations from the database
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        rec_ref = db.reference(f"recommendations/{user_id}")
        recommendation = rec_ref.get()

        recommendations_text.config(state=tk.NORMAL)
        if recommendation:
            recommendations_text.insert(tk.END, recommendation['ad'])
        else:
            recommendations_text.insert(tk.END, "No recommendations at this time.")
        recommendations_text.config(state=tk.DISABLED)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

# Main function to start the client-server
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Hide the main window to ask for server port

    # Prompt the user to input the local port
    local_port = simpledialog.askinteger("Port", "Insert local port:")
    root.destroy()

    if local_port:
        try:
            # Get the local IP address
            host = socket.gethostbyname(socket.gethostname())
        except Exception:
            host = '127.0.0.1'  # Fallback to localhost if unable to get IP
        # Initialize the P2P Chat Application
        app = P2PChatApp(host, local_port)
        app.root.mainloop()
    else:
        messagebox.showerror("Error", "Invalid port! Application will now end.")

# Main function to start the GUI application
if __name__ == "__main__":
    start_peer()
