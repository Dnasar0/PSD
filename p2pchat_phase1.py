import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
import datetime
import secrets
import Peer
import Tk

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID


# Directory to store certificates and keys
CERT_DIR = "certificates"
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

# Path to the ACL file that stores trusted peers
ACL_FILE = "trusted_peers.json"


def configure_aes_key(shared_key):
    # Derive a 256-bit AES key from the shared key
    aes_key = hashlib.sha256(shared_key).digest()[:32]  # Use the first 32 bytes as AES key
    return aes_key

# Function to generate key pair
def generate_key_pair():
    dh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    return dh_private_key.public_key(), dh_private_key

# Main P2P Chat Application class
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = {}  # Dictionary to store connected peers
        self.server_socket = None  # Server socket

        # Load or generate key pair and certificate
        self.private_key, self.certificate = self.load_or_generate_certificate()
        self.certificate_bytes = self.certificate.public_bytes(serialization.Encoding.PEM)

        # Load ACL (Access Control List)
        self.trusted_peers = self.load_acl()

        # Initialize the GUI
        self.T = Tk.Tk(self, host, port)
        self.root = self.T.get_root()

        # Start the server in a new thread to allow simultaneous execution
        threading.Thread(target=self.start_server, daemon=True).start()

    def load_or_generate_certificate(self):
        """
        Loads or generates a DH key pair and a self-signed certificate.
        """
        cert_path = os.path.join(CERT_DIR, f"peer_{self.port}.pem")
        key_path = os.path.join(CERT_DIR, f"peer_{self.port}_key.pem")
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            # Load keys and certificate if they already exist
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(cert_path, "rb") as cert_file:
                certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
            return private_key, certificate
        else:
            public_key, private_key = generate_key_pair()

            # Generate a self-signed certificate for the peer
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"Peer_{self.port}")
            ])
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Certificate valid for 10 years
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(f"Peer_{self.port}")]),
                critical=False
            ).sign(private_key, hashes.SHA256(), default_backend())

            # Save the keys and certificate
            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            return private_key, certificate

    def load_acl(self):
        """
        Loads the list of trusted peers (ACL) from a JSON file.
        """
        if os.path.exists(ACL_FILE):
            with open(ACL_FILE, "r") as f:
                return json.load(f)
        else:
            return []

    def save_acl(self):
        """
        Saves the list of trusted peers to the ACL file.
        """
        with open(ACL_FILE, "w") as f:
            json.dump(self.trusted_peers, f, indent=4)

    def start_server(self):
        """
        Starts the server to accept connections from peers.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Listening on {self.host}:{self.port}")
        except Exception as e:
            print(f"Error starting server: {e}")
            messagebox.showerror("Error", f"Unable to start server: {e}")
            sys.exit(1)

        while True:
            try:
                conn, addr = self.server_socket.accept()
                peer_ip, _ = addr  # Ignore the ephemeral port

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
            # Exchange certificates
            peer_cert_bytes = self.receive_all(conn)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            print("Received certificate")

            # Send own certificate
            conn.sendall(self.certificate_bytes)
            print("Sent certificate")

            # Receive peer's DH public key
            peer_dh_public_key_bytes = self.receive_all(conn)  
            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())
            
            self.dh_public_key, self.dh_private_key = generate_key_pair()

            # Send DH public key to peer
            dh_public_key_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )   
            conn.sendall(dh_public_key_bytes)    
            
            shared_key = self.dh_private_key.exchange(ec.ECDH(), peer_dh_public_key)
            aes_key = configure_aes_key(shared_key)

            # Receive peer's listening port
            msg_length_bytes = conn.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed by peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_port = self.receive_exact(conn, msg_length)
            peer_listening_port = int(self.decrypt_message(encrypted_port, aes_key))

            # Send our own listening port
            encrypted_port = self.encrypt_message(str(self.port), aes_key)
            msg_length = len(encrypted_port)
            conn.sendall(msg_length.to_bytes(4, byteorder='big'))
            conn.sendall(encrypted_port)
            peer = Peer.Peer(peer_ip, peer_listening_port, conn, peer_certificate, aes_key, self.dh_private_key)
            self.peers[(peer_ip, peer_listening_port)] = peer  # Use tuple as key
            print(f"Trusted Peer Connected: {peer_ip}:{peer_listening_port}")
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            
        except Exception as e:
            print(f"Error establishing connection with {peer_ip}: {e}")
            conn.close()

    def connect_to_peer(self):
        """
        Connects to a remote peer using user-provided IP and port.
        """
        peer_ip = self.T.peer_ip_entry.get()
        peer_port = self.T.peer_port_entry.get()

        # Input validation
        if not self.validate_ip(peer_ip) or not peer_port.isdigit():
            messagebox.showerror("Error", "Invalid IP or port!")
            return

        peer_port = int(peer_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Send own certificate
            sock.sendall(self.certificate_bytes)
            print("Sent certificate")

            # Receive peer's certificate
            peer_cert_bytes = self.receive_all(sock)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            print("Received certificate")
            
            self.dh_public_key, self.dh_private_key = generate_key_pair()                            

            # Send the public DH key to the peer
            dh_public_key_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(dh_public_key_bytes)

            # Receive the peer's DH public key
            peer_dh_public_key_bytes = self.receive_all(sock)            

            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())

            shared_key = self.dh_private_key.exchange(ec.ECDH(), peer_dh_public_key)
                        
            aes_key = configure_aes_key(shared_key)

            # Send our own listening port
            encrypted_port = self.encrypt_message(str(self.port), aes_key)
            msg_length = len(encrypted_port)
            sock.sendall(msg_length.to_bytes(4, byteorder='big'))
            sock.sendall(encrypted_port)

            # Receive peer's listening port
            msg_length_bytes = sock.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed by peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_port = self.receive_exact(sock, msg_length)
            peer_listening_port = int(self.decrypt_message(encrypted_port, aes_key))

            peer = Peer.Peer(peer_ip, peer_listening_port, sock, peer_certificate, aes_key)
            self.peers[(peer_ip, peer_listening_port)] = peer  # Use tuple as key
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            messagebox.showinfo("Connection well-established", f"Connected & trusted {peer_ip}:{peer_listening_port}")

            self.T.setup_main_menu()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to {peer_ip}:{peer_port}\nError: {e}")

    def validate_ip(self, ip):
        """
        Validates if the provided IP is valid.
        """
        parts = ip.split(".")
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

    def receive_messages(self, peer):
        """
        Receives messages from the peer and updates the chat interface.
        """
        while True:
            try:
                msg_length_bytes = peer.connection.recv(4)
                if not msg_length_bytes:
                    raise Exception("Connection closed by peer!")
                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                encrypted_message = self.receive_exact(peer.connection, msg_length)
                message = self.decrypt_message(encrypted_message, peer.aes_key)
                print(f"Message received from {peer.ip}:{peer.port}: {message}")

                if peer.chat_window:
                    self.T.update_chat_window(peer, message, sender=False)
                self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")

            except Exception as e:
                print(f"Connection to {peer.ip}:{peer.port} closed: {e}")
                peer.connection.close()
                del self.peers[(peer.ip, peer.port)]  # Use tuple as key
                break

    def send_message(self, peer, message_var, text_area):
        """
        Sends a message to the peer using AES encryption.
        """
        message = message_var.get()
        if message:
            message_var.set("")  # Clear the input field

            try:
                encrypted_message = self.encrypt_message(message, peer.aes_key)
                msg_length = len(encrypted_message)
                peer.connection.sendall(msg_length.to_bytes(4, byteorder='big'))
                peer.connection.sendall(encrypted_message)
                print("Sent message")

                self.T.update_chat_window(peer, message, sender=True)
                self.save_chat_to_file(peer, f"You: {message}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")

    def save_chat_to_file(self, peer, message):
        """
        Saves the conversation to a history file.
        """
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(message + '\n')

    def encrypt_message(self, message, aes_key):
        """
        Encrypts the message using AES in GCM mode to ensure integrity and confidentiality.
        Returns the nonce concatenated with the ciphertext and the tag.
        """
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, encrypted_message, aes_key):
        """
        Decrypts the message using AES in GCM mode.
        Expects the message to be in the format nonce + ciphertext + tag.
        """
        nonce = encrypted_message[:12]
        tag = encrypted_message[-16:]
        ciphertext = encrypted_message[12:-16]
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')

# Main function to start the client-server
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Hide the main window to ask for server port

    local_port = simpledialog.askinteger("Port", "Insert local port:")
    root.destroy()

    if local_port:
        try:
            host = socket.gethostbyname(socket.gethostname())  # Get local IP
        except Exception:
            host = '127.0.0.1'  # Fallback to localhost if unable to get IP
        app = P2PChatApp(host, local_port)
        app.root.mainloop()
    else:
        messagebox.showerror("Error", "Invalid port! Application will now end.")

if __name__ == "__main__":
    start_peer()
