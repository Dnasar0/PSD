import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

# Import cryptographic primitives for encryption and key management
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # For ECDH key exchange
from cryptography.hazmat.primitives import serialization  # For key serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption

# Import Firebase Admin SDK modules for database interaction
import firebase_admin
from firebase_admin import credentials, db

import ConnectionEntity
import TkApp

if not firebase_admin._apps:
    cred = credentials.Certificate("psdproject-6e38f-firebase-adminsdk-icq10-3708af2f3d.json")
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://psdproject-6e38f-default-rtdb.europe-west1.firebasedatabase.app/'
    })

# Directories to store peers list
PEERS_DIR = "peersList"

# Create directories if they do not already exist
for directory in [PEERS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Function to derive an AES key from the shared ECDH key
def derive_aes_key(shared_key):
    # Use SHA-256 hash function to derive a 256-bit AES key
    aes_key = hashlib.sha256(shared_key).digest()
    return aes_key

def derive_key_from_attribute(attribute):
    # Hash the attribute to create a consistent AES key
    return hashlib.sha256(attribute.encode()).digest()

# Function to sanitize strings for Firebase paths by replacing invalid characters
def sanitize_for_firebase_path(s):
    # Replace invalid characters in Firebase paths with underscores
    return s.replace('.', '_').replace('$', '_').replace('#', '_').replace('[', '_').replace(']', '_').replace('/', '_')

# Main P2P Chat Application class
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host  # Local IP address
        self.port = port  # Local port number
        self.peers = {}  # Dictionary to store connected peers and groups
        self.server_socket = None  # Server socket for listening
        self.messages_loaded = False  # Flag to indicate if messages have been loaded

        # Generate ECDH key pair for secure communication
        self.private_key, self.public_key = self.generate_ecdh_key_pair()
        # Serialize the public key to bytes for transmission
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Initialize the TkApp class with the existing root instance
        self.gui_app = TkApp.TkApp(self, host, port)        

        # Bind the window close event to save peers before exiting
        self.gui_app.root.protocol("WM_DELETE_WINDOW", self.on_close)

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
        self.gui_app.root.destroy()

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
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, conn, peer_public_key, session_aes_key, is_group)
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
            peer_ip = self.gui_app.peer_ip_entry.get()
            peer_port = self.gui_app.peer_port_entry.get()

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
            # Do nothing here, as group connection is handled by the GUI
            pass

    def connect_to_group(self, group_name):
        """
        Connects to a group chat by name, after checking if the user has access to the group based on their topics of interest.
        """
        # First, get the user's topics of interest from Firebase
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_data = user_ref.get()
        user_topics = user_data.get('topics', []) if user_data else []

        # Get the group's topic from Firebase
        group_id = sanitize_for_firebase_path(group_name)
        group_ref = db.reference(f"groups/{group_id}")
        group_data = group_ref.get()
        group_topic = group_data.get('topic') if group_data else None

        if not group_topic:
            # If the group doesn't exist yet, prompt the user to set the topic for the new group
            messagebox.showinfo("New Group", f"The group '{group_name}' does not exist. Creating a new group.")
            # Ask the user to select a topic for the new group from their topics of interest
            if not user_topics:
                messagebox.showerror("Error", "You have not selected any topics of interest.")
                return

            topic = simpledialog.askstring("Group Topic", "Select a topic for the new group:\n" + "\n".join(user_topics))
            if not topic or topic not in user_topics:
                messagebox.showerror("Error", "Invalid topic selected for the group.")
                return

            # Save the group topic to Firebase
            group_ref.set({'topic': topic})
            group_topic = topic  # Set group_topic for access check
        else:
            # Group already exists, topic is known
            pass

        # Check if the group topic is in the user's topics of interest
        if group_topic not in user_topics:
            messagebox.showerror("Access Denied", f"You do not have access to the group '{group_name}' as it is not in your topics of interest.")
            return

        # Proceed to connect to the group
        if group_name not in self.peers:
            # Create a ConnectionEntity for the group
            entity = ConnectionEntity.ConnectionEntity(None, None, None, None, None, is_group=True, group_name=group_name)
            self.peers[group_name] = entity
            # Start a thread to receive messages from the group
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            messagebox.showinfo("Connected to Group", f"Connected to group '{group_name}'")
            self.gui_app.setup_main_menu()
        else:
            messagebox.showinfo("Info", f"Already connected to group '{group_name}'")

    def connect_to_peer_ui(self, peer_ip, peer_port):
        """
        Connects to a peer and updates the UI accordingly.
        """
        try:
            self.connect_to_peer(peer_ip, peer_port)
            # Inform the user upon successful connection
            self.gui_app.root.after(0, lambda: messagebox.showinfo("Connection Established", f"Connected to {peer_ip}:{peer_port} as Peer"))
            self.gui_app.root.after(0, self.gui_app.setup_main_menu)
        except Exception as e:
            # Show an error message if the connection fails
            self.gui_app.root.after(0, lambda: messagebox.showerror("Connection Error", f"Could not connect to {peer_ip}:{peer_port}\nError: {e}"))

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
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, sock, peer_public_key, session_aes_key, is_group)
            self.peers[(peer_ip, peer_port)] = entity  # Use tuple as key
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
                        self.gui_app.update_chat_window(entity, f"{entity.ip}:{entity.port}: {message}")
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
                            self.gui_app.update_chat_window(group_entity, display_message)

        # Start listening to the group messages
        group_ref.listen(listener)

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
                self.gui_app.update_chat_window(entity, f"You: {message}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")

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
    
    # Function to encrypt a message with an attribute key
    def encrypt_message_with_attribute(message, attribute):
        aes_key = derive_key_from_attribute(attribute)
        nonce = secrets.token_bytes(12)  # Generate a random nonce for GCM
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce)).encryptor()
        ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
        return nonce + ciphertext + encryptor.tag

    # Function to decrypt a message with an attribute key
    def decrypt_message_with_attribute(encrypted_message, attribute):
        aes_key = derive_key_from_attribute(attribute)
        nonce = encrypted_message[:12]
        tag = encrypted_message[-16:]
        ciphertext = encrypted_message[12:-16]
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag)).decryptor()
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            print("Decryption failed:", e)
            return None    

    def perform_privacy_preserving_search(self, keywords):
        """
        Searches all connected peers/groups for messages containing the keywords using ORAM.
        """
        results = []

        # Collect all messages into a list
        all_messages = []

        # Ensure messages are loaded
        self.load_all_messages()

        # For each connected entity, retrieve the cached messages
        for entity_key, entity in self.peers.items():
            if entity.messages:
                # Simulate ORAM by shuffling the messages
                import random
                random.shuffle(entity.messages)

                for msg in entity.messages:
                    message = msg['message']
                    if any(keyword.lower() in message.lower() for keyword in keywords):
                        if entity.is_group:
                            results.append(f"Group '{entity.group_name}', Message: {message}")
                        else:
                            results.append(f"Peer {entity.ip}:{entity.port}, Message: {message}")
                    else:
                        # Dummy operation to simulate ORAM access pattern
                        pass  # Do nothing

        return results

    def load_all_messages(self):
        """
        Loads messages from all connected peers and groups into memory.
        """
        if self.messages_loaded:
            return  # Messages are already loaded

        for entity_key, entity in self.peers.items():
            entity.messages = []
            if entity.is_group:
                # Load messages from the group's reference in Firebase
                group_id = sanitize_for_firebase_path(entity.group_name)
                group_ref = db.reference(f"groups/{group_id}/messages")
                messages = group_ref.get()
                if messages:
                    for msg_key in messages:
                        message_data = messages[msg_key]
                        # Handle both dict and string formats
                        if isinstance(message_data, dict):
                            message = message_data.get('message', '')
                            sender = message_data.get('sender', '')
                        else:
                            message = message_data
                            sender = ''
                        entity.messages.append({'sender': sender, 'message': message})
            else:
                # Load messages from the chat's reference in Firebase
                chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
                chat_ref = db.reference(f"chats/{chat_id}")
                messages = chat_ref.get()
                if messages:
                    for msg_key in messages:
                        message_data = messages[msg_key]
                        # Handle both dict and string formats
                        if isinstance(message_data, dict):
                            message = message_data.get('message', '')
                            sender = message_data.get('sender', '')
                        else:
                            message = message_data
                            sender = ''
                        entity.messages.append({'sender': sender, 'message': message})

        self.messages_loaded = True  # Set the flag to indicate messages are loaded

    def get_recommendations(self):
        """
        Analyzes the client's own message history to determine recommended topics and groups.
        """
        # Collect all messages sent by the client
        user_id = f"{self.host}:{self.port}"
        messages = []

        # Load messages from all connected entities
        self.load_all_messages()

        # Go through all cached messages
        for entity_key, entity in self.peers.items():
            if entity.messages:
                for msg in entity.messages:
                    sender = msg.get('sender', '')
                    message = msg.get('message', '')
                    if sender == user_id or sender == 'You':
                        messages.append(message)

        # Now analyze the messages to extract topics
        topics_keywords = {
            'Cars': ['car', 'automobile', 'vehicle', 'drive'],
            'Music': ['music', 'song', 'album', 'band', 'artist'],
            'Soccer': ['soccer', 'football', 'goal', 'match', 'player'],
            'Basketball': ['basketball', 'nba', 'hoops', 'dunk', 'player'],
            'Cybersecurity': ['cybersecurity', 'hacking', 'security', 'malware', 'encryption'],
            'AI-Artificial Intelligence': ['ai', 'artificial intelligence', 'machine learning', 'neural network'],
            'IoT-Internet of Things': ['iot', 'internet of things', 'smart device', 'sensor', 'connectivity']
        }

        topics_count = {}

        for message in messages:
            message_lower = message.lower()
            for topic, keywords in topics_keywords.items():
                for keyword in keywords:
                    if keyword in message_lower:
                        topics_count[topic] = topics_count.get(topic, 0) + 1

        # Now get the topics sorted by count
        recommended_topics = sorted(topics_count.items(), key=lambda item: item[1], reverse=True)

        # Now get the groups related to these topics
        groups_ref = db.reference("groups")
        groups_data = groups_ref.get()
        recommended_groups = []

        if groups_data:
            for group_name, group_info in groups_data.items():
                group_topic = group_info.get('topic')
                for topic, _ in recommended_topics:
                    if group_topic == topic:
                        recommended_groups.append((group_name, group_topic))
                        break

        # Return the recommended topics and groups
        return recommended_topics, recommended_groups

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
        app.gui_app.root.mainloop()
    else:
        messagebox.showerror("Error", "Invalid port! Application will now end.")

# Main function to start the GUI application
if __name__ == "__main__":
    start_peer()
