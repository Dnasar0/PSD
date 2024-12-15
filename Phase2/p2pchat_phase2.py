# p2pchat_phase2.py
import base64
from random import getrandbits
import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
import secrets
import time  # Added import for timestamps
import uuid  # Added import for unique message IDs

# Import cryptographic primitives for encryption and key management
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec # For ECDH key exchange
from cryptography.hazmat.primitives import serialization  # For key serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # For AES encryption
from cryptography.hazmat.primitives import hashes, padding as _Padding  # For HMAC and Padding

# Import Firebase Admin SDK modules for database interaction
import firebase_admin
from firebase_admin import credentials, db

# Import AWS SDK for Python (Boto3) for S3 storage
import boto3
import sslib.randomness
import sslib.util

import InMemoryORAM as ORAM

# Lightweight pre-trained model
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')
from sklearn.metrics.pairwise import cosine_similarity

# Cosmos DB 
from azure.cosmos import CosmosClient, exceptions, PartitionKey

from sslib import shamir

import ConnectionEntity
import TkApp

def decode_public_key(encoded_public_key):
    # Decode the Base64 encoded public key
    public_key_pem = base64.b64decode(encoded_public_key)

    # Deserialize the PEM data to get the public key object
    public_key = serialization.load_pem_public_key(public_key_pem)

    return public_key

def bytes_to_base64(b):
    return base64.b64encode(b).decode('utf-8')

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

# Function to sanitize strings for Firebase paths by replacing invalid characters
def sanitize_for_firebase_path(s):
    # Replace invalid characters in Firebase paths with underscores
    return s.replace('.', '_').replace('$', '_').replace('#', '_').replace('[', '_').replace(']', '_').replace('/', '_')

# Main P2P Chat Application class
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = {}
        self.peers_historic = {}
        self.server_socket = None
        self.messages_loaded = False
        self.aes_key = None
        
        self.topic_embeddings = self.generate_topic_embeddings()

        # Storage configuration
        self.s3_bucket_names = ['projetopsd1', 'projetopsd2', 'projetopsd3', 'projetopsd4']
        self.firebase_refs = ['projetopsd1', 'projetopsd2', 'projetopsd3', 'projetopsd4']
        self.cosmos_names = ['projetopsd1', 'projetopsd2', 'projetopsd3', 'projetopsd4']
        self.s3_client, self.cosmos_client = self.initialize_services()
        
        self.private_key, self.public_key = self.generate_ecdh_key_pair()

        self.initialize_user()
        
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
        
    def getFirebaseRefs(self):
        return self.firebase_refs
    
    def getS3BucketNames(self):
        return self.s3_bucket_names
    
    def getCosmosNames(self):
        return self.cosmos_names
    
    # Initialize Firebase and S3 clients
    def initialize_services(self):

        # Initialize Firebase Admin SDK with credentials and database URL
        if not firebase_admin._apps:
            #cred = credentials.Certificate("psdproject-6e38f-firebase-adminsdk-icq10-3708af2f3d.json")
            cred = credentials.Certificate("projetopsd-5a681-19d45fdfc118.json")
            #cred = credentials.Certificate("projetopsd-6abec-firebase-adminsdk-tf6mp-1a2522b1cb.json")
            firebase_admin.initialize_app(cred, {
                #'databaseURL': 'https://psdproject-6e38f-default-rtdb.europe-west1.firebasedatabase.app/'
                'databaseURL': 'https://projetopsd-5a681-default-rtdb.europe-west1.firebasedatabase.app/'
                #'databaseURL': 'https://projetopsd-6abec-default-rtdb.europe-west1.firebasedatabase.app/'
            })

            # Initialize AWS S3 client
            s3_client = boto3.client(
                's3',
                # Uncomment and set your AWS credentials if needed
                #aws_access_key_id='AKIAZI2LGQDRWWJFA5RX',
                aws_access_key_id='AKIAQR5EPGH6RTK32M56',
                #aws_access_key_id='AKIATG6MGI4GPA4WUFHM',
                #aws_secret_access_key='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',
                aws_secret_access_key='z4TCt1JyLPFeYoLEO/j7ei+550sMmuUdusoxPnSw',
                #aws_secret_access_key='fyQscUkArOELwTDSDQ4Q6Wew+K++l1uDX1Ig3atX',
                region_name='us-east-1' #'us-east-1' 
            )  
            
        endpoint = "https://projetopsd.documents.azure.com:443/"
        key = "8623mjb8FhTWVRLmgqeXaq5vLs5qZHuGXX4vSzm3WcXdf9DuHskbEbPpEgxoSY14HlRRMLffbvBeACDbiBWFMQ=="
        
        client = CosmosClient(endpoint, key)

        return s3_client,client

    def create_user_in_three_services(
        self,
        host, 
        port, 
        s3_client, 
        cosmos_client,
        s3_buckets,  # List of bucket names
        fb_replicas,  # List of Firebase database references
        cosmos_names, # List of Cosmos DB names
        public_key
    ):
        """
        Creates a user in multiple Firebase replicas and multiple S3 buckets with Shamir's Secret Sharing for the public key.
        """
        user_id = f"{sanitize_for_firebase_path(host)}_{port}"

        # Convert public key to a big integer (or byte representation)
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_bytes = bytes.fromhex(public_key_pem.hex())  # Convert to bytes

        # Shamir's Secret Sharing parameters
        n = len(s3_buckets)  # Total number of shares
        t = n // 2 + 1  # Threshold: Minimum shares required to reconstruct

        # Split the public key into shares
        shares = shamir.split_secret(public_key_bytes, t, n)
        
        prime_mod = bytes_to_base64(shares['prime_mod'])

        # User data to store
        base_user_data = {
            'topics': ['None'],
            'prime': prime_mod,
            'threshold': t
        }

        # Store data in all Firebase replicas
        for i, replica in enumerate(fb_replicas):
            try:
                user_ref = db.reference(f"{replica}/users/{user_id}")
                user_data = base_user_data.copy()
                # Correctly access the public key share from the tuple and convert it to hex
                user_data['public_key_share'] = shares['shares'][i][1].hex()  # Get the byte array from the tuple and convert it to hex
                user_ref.set(user_data)
                print(f"User created in Firebase {replica}: {user_id}")
            except Exception as e:
                print(f"Failed to create user in Firebase {replica}: {e}")

        # Store data in all S3 buckets
        for i, bucket_name in enumerate(s3_buckets):
            try:
                user_data = base_user_data.copy()
                # Correctly access the public key share from the tuple and convert it to hex
                user_data['public_key_share'] = shares['shares'][i][1].hex()  # Get the byte array from the tuple and convert it to hex
                s3_key = f"users/{user_id}.json"
                s3_client.put_object(
                    Bucket=bucket_name,
                    Key=s3_key,
                    Body=json.dumps(user_data),
                    ContentType='application/json'
                )
                print(f"User data uploaded to S3 bucket {bucket_name}: {user_id}")
            except Exception as e:
                print(f"Failed to upload user data to S3 bucket {bucket_name}: {e}")
                    
        # Store data in all Cosmos DB databases
        for i, cosmos_name in enumerate(cosmos_names):
            try:
                # Get or create the database
                database = cosmos_client.create_database_if_not_exists(id=cosmos_name)

                # Get or create the container (with "user_id" as the partition key)
                container = database.create_container_if_not_exists(
                    id='users',
                    partition_key=PartitionKey(path="/id"),  # Use "user_id" as the partition key
                )

                # Prepare user data
                user_data = base_user_data.copy()
                user_data['public_key_share'] = shares['shares'][i][1].hex()  # Convert public key share to hex
                user_data['id'] = user_id # Partition key requirement

                # Add user data to Cosmos DB
                container.create_item(body=user_data)
                print(f"User data added to Cosmos DB {cosmos_name}: {user_id}")
            except exceptions.CosmosResourceExistsError:
                print(f"User already exists in Cosmos DB {cosmos_name}: {user_id}")
            except Exception as e:
                print(f"Failed to create user in Cosmos DB {cosmos_name}: {e}")    

    def user_exists_in_databases(self, user_id):
        """
        Checks if the user exists in Firebase replicas or S3 buckets.
        """
        user_found = False

        # Check Firebase replicas
        for replica in self.firebase_refs:
            try:
                user_data = db.reference(f"{replica}/users/{user_id}").get()
                if user_data:
                    print(f"User found in Firebase {replica}: {user_id}")
                    user_found = True
            except Exception as e:
                print(f"Error checking user in Firebase {replica}: {e}")
                
        if not user_found:

            # Check S3 buckets
            for bucket_name in self.s3_bucket_names:
                try:
                    s3_key = f"users/{user_id}.json"
                    response = self.s3_client.get_object(Bucket=bucket_name, Key=s3_key)
                    user_data = json.loads(response['Body'].read().decode('utf-8'))
                    print(f"User found in S3 bucket {bucket_name}: {user_id}")
                    user_found = True
                except self.s3_client.exceptions.NoSuchKey:
                    print(f"No user data found in S3 bucket {bucket_name}.")
                except Exception as e:
                    print(f"Error checking user in S3 bucket {bucket_name}: {e}")
                    
        if not user_found:
                    
            for cosmo_name in self.cosmos_names:
                try:
                    database = self.cosmos_client.get_database_client(cosmo_name)
                    container = database.get_container_client('users')
                    user_data = container.read_item(item=user_id, partition_key=user_id)
                    print(f"User found in Cosmos DB {cosmo_name}: {user_id}")
                    user_found = True
                except exceptions.CosmosResourceNotFoundError:
                    print(f"No user data found in Cosmos DB {cosmo_name}.")
                except Exception as e:
                    print(f"Error checking user in Cosmos DB {cosmo_name}: {e}")

        return user_found

    def initialize_user(self):
        """
        Initializes the user by reconstructing the public key if possible,
        or regenerating it if the user does not exist.
        """
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"

        if self.user_exists_in_databases(user_id):

            if self.reconstruct_public_key(user_id):
                return
            
            # If user does not exist or reconstruction fails, regenerate keys
            print("Reconstruction failed. Generating new key pair...")
            self.private_key, self.public_key = self.generate_ecdh_key_pair()
            self.create_user_in_three_services(
                self.host, 
                self.port, 
                self.s3_client, 
                self.cosmos_client,
                self.s3_bucket_names, 
                self.firebase_refs, 
                self.cosmos_names,
                self.public_key
            )
            return
            
        else:
           # If user does not exist or reconstruction fails, regenerate keys
           print("User does not exist. Adding to databases...")
           self.private_key, self.public_key = self.generate_ecdh_key_pair()
           self.create_user_in_three_services(
               self.host, 
               self.port, 
               self.s3_client, 
               self.cosmos_client,
               self.s3_bucket_names, 
               self.firebase_refs, 
               self.cosmos_names,
               self.public_key
           )

    def reconstruct_public_key(self, user_id):
        """
        Reconstruct the user's public key from available shares in Firebase, S3, and Cosmos DB sequentially.
        """
        shares = []
        prime = None
        threshold = None
        recovered_secret = None

        # Step 1: Try to fetch shares from Firebase
        for replica in self.firebase_refs:
            try:
                user_data = db.reference(f"{replica}/users/{user_id}").get()
                if user_data:
                    shares.append(user_data['public_key_share'])
                    prime = base64.b64encode(user_data['prime'].encode('utf-8'))
                    threshold = user_data['threshold']
                    print(f"Fetched share from Firebase {replica}.")
            except Exception as e:
                print(f"Failed to fetch data from Firebase {replica}: {e}")

        if shares and prime and threshold:
        
            # Attempt reconstruction with Firebase data
            recovered_secret = self.can_reconstruct_secret(shares, threshold, prime)
            if recovered_secret is not None:
                print("Public key successfully reconstructed from Firebase.")
                return recovered_secret

        # Step 2: Try to fetch shares from S3
        shares = []  # Reset shares for the next attempt
        for bucket_name in self.s3_bucket_names:
            try:
                s3_key = f"users/{user_id}.json"
                response = self.s3_client.get_object(Bucket=bucket_name, Key=s3_key)
                user_data = json.loads(response['Body'].read().decode('utf-8'))
                shares.append(user_data['public_key_share'])
                prime = base64.b64encode(user_data['prime'].encode('utf-8'))
                threshold = user_data['threshold']
                print(f"Fetched share from S3 bucket {bucket_name}.")
            except self.s3_client.exceptions.NoSuchKey:
                print(f"No data found for user {user_id} in S3 bucket {bucket_name}.")
            except Exception as e:
                print(f"Failed to fetch data from S3 bucket {bucket_name}: {e}")
                
        if shares and prime and threshold:                    

            # Attempt reconstruction with S3 data
            recovered_secret = self.can_reconstruct_secret(shares, threshold, prime)
            if recovered_secret is not None:
                print("Public key successfully reconstructed from S3.")
                return recovered_secret

        # Step 3: Try to fetch shares from Cosmos DB
        shares = []  # Reset shares for the next attempt
        for cosmos_name in self.cosmos_names:
            try:
                database = self.cosmos_client.get_database_client(cosmos_name)
                container = database.get_container_client("users")
                user_data = container.read_item(user_id, partition_key=user_id)
                if user_data:
                    shares.append(user_data['public_key_share'])
                    prime = base64.b64encode(user_data['prime'].encode('utf-8'))
                    threshold = user_data['threshold']
                    print(f"Fetched share from Cosmos DB {cosmos_name}.")
            except exceptions.CosmosResourceNotFoundError:
                print(f"No data found for user {user_id} in Cosmos DB {cosmos_name}.")
            except Exception as e:
                print(f"Failed to fetch data from Cosmos DB {cosmos_name}: {e}")
                
        if shares and prime and threshold:                

            # Attempt reconstruction with Cosmos DB data
            recovered_secret = self.can_reconstruct_secret(shares, threshold, prime)
            if recovered_secret is not None:
                print("Public key successfully reconstructed from Cosmos DB.")
                return recovered_secret

        # If all attempts fail
        print("Failed to reconstruct the public key from all sources.")
        return None

    def can_reconstruct_secret(self, shares, threshold, prime_mod):
        """
        Attempts to reconstruct the secret using Shamir's Secret Sharing.
        """
        if len(shares) >= threshold:
            try:
                # Decode the shares
                shares_list = []
                for idx, share in enumerate(shares):
                    share_bytes = base64.b64decode(share)  # Decode base64 share
                    shares_list.append((idx, share_bytes))

                # Rebuild the shared_data dictionary for use in Shamir's Secret Sharing
                shared_data = {
                    'shares': shares_list,
                    'required_shares': threshold,
                    'prime_mod': prime_mod
                }

                # Attempt to recover the secret
                return shamir.recover_secret(shared_data)
            except Exception as e:
                print(f"Failed to reconstruct the public key: {e}")
        else:
            print("Insufficient shares to reconstruct the public key.")

        return None     
        
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
        Removes stale connections from previous sessions.
        """
        # Prepare a dictionary to store only current session's peers
        current_peers = {}
        print(self.peers_historic.items()) 

        # Populate the current session's peers
        for key, entity in self.peers_historic.items():
            if entity.is_group:
                key = f"group:{entity.group_name}"
                current_peers[key] = {
                    'is_group': True,
                    'group_name': entity.group_name
                }
            else:
                key = f"peer:{entity.ip}:{entity.port}"
                current_peers[key] = {
                    'is_group': False,
                    'ip': entity.ip,
                    'port': entity.port,
                    'session_key': entity.aes_key.hex() if entity.aes_key else None
                }

        # Write only current session's peers to the file
        filename = self.get_peers_filename()
        with open(filename, 'w') as f:
            json.dump(list(current_peers.values()), f)
        print(f"Peers saved to file {filename}.")


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
                    if group_name not in self.peers_historic: #self.peers:
                        self.connect_to_group(group_name)
                else:
                    ip = peer_info['ip']
                    port = peer_info['port']
                    # Attempt to connect to peer if not already connected
                    if (ip, port) not in self.peers_historic: #self.peers:
                        entity = ConnectionEntity.ConnectionEntity(
                            ip,
                            port,
                            None,
                            None,
                            aes_key=bytes.fromhex(peer_info['session_key']) if peer_info['session_key'] else None,
                            is_group=False
                        )
                        self.peers_historic[(ip, port)] = entity                        
                        threading.Thread(target=self.connect_to_peer, args=(ip, port,True), daemon=True).start()
        else:
            print("No previous peers to load.")
            
    def retrieve_aes_key(self, peer_ip, peer_port):
        """
        Retrieve the AES session key for a specific peer from the peer list.
        """
        # Generate the filename for the peer list JSON
        filepath = self.get_peers_filename()
        

        if not os.path.exists(filepath):
            print(f"No peer list found at {filepath}")
            return None

        try:
            # Load the peer list
            with open(filepath, 'r') as f:
                peers_list = json.load(f)

            # Search for the matching peer in the list
            for peer_info in peers_list:
                if not peer_info['is_group'] and peer_info['ip'] == peer_ip and peer_info['port'] == peer_port:
                    session_key = peer_info.get('session_key', None)
                    if session_key:
                        # Convert the session key back to bytes (if stored as hex or base64)
                        return bytes.fromhex(session_key)  # Use appropriate decoding if necessary
            print(f"Peer {peer_ip}:{peer_port} not found in peer list.")
            return None
        except Exception as e:
            print(f"Error reading peer list: {e}")
            return None                    

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
            # Step 1: Receive handshake flag ("already_connected" or "new_connection")
            handshake_flag = conn.recv(1024).decode()
            if not handshake_flag:
                raise Exception("Connection closed during handshake!")
            print(f"Handshake flag received: {handshake_flag}")

            if handshake_flag == "already_connected":
                
                conn.sendall("ACK1".encode())

                # Step 3: Receive peer's port
                peer_port_bytes = conn.recv(4)
                if not peer_port_bytes:
                    raise Exception("Connection closed while receiving peer's port!")
                peer_port = int.from_bytes(peer_port_bytes, byteorder="big")
                print(f"Received peer's port: {peer_port}")

                # Step 4: Retrieve the session AES key
                session_aes_key = self.retrieve_aes_key(peer_ip, peer_port)
                if session_aes_key is None:
                    raise Exception(f"Could not retrieve session key for {peer_ip}:{peer_port}")
                print("Retrieved session AES key")
            elif handshake_flag == "new_connection":
                
                conn.sendall("ACK0".encode())
                # Step 2: Perform ECDH key exchange
                # Receive peer's public key
                peer_public_key_bytes = self.receive_all(conn)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
                print("Received peer's public key")

                # Send own public key
                conn.sendall(self.public_key_bytes)
                print("Sent own public key")

                # Generate shared secret and derive AES session key
                shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
                session_aes_key = derive_aes_key(shared_key)
                print("Generated new AES session key")

                # Step 3: Receive peer's port
                peer_port_bytes = conn.recv(4)
                if not peer_port_bytes:
                    raise Exception("Connection closed while receiving peer's port!")
                peer_port = int.from_bytes(peer_port_bytes, byteorder="big")
                print(f"Received peer's port: {peer_port}")
            else:
                raise Exception(f"Unknown handshake flag: {handshake_flag}")

            # Step 5: Receive peer's connection type and listening port
            msg_length_bytes = conn.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed while receiving connection type and port!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder="big")
            encrypted_info = self.receive_exact(conn, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)
            print(f"Received peer's connection type: {connection_type}, port: {peer_listening_port}")

            # Step 6: Send own connection type and port to the peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            self.aes_key = session_aes_key
            msg_length = len(encrypted_info)
            conn.sendall(msg_length.to_bytes(4, byteorder="big"))
            conn.sendall(encrypted_info)
            print("Sent connection type and port info")

            # Step 7: Determine if the connection is to a group or an individual
            is_group = (connection_type == 'group')

            # Step 8: Create a `ConnectionEntity` to represent the connection
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, conn, None, session_aes_key, is_group)
            self.peers[(peer_ip, peer_listening_port)] = entity
            self.peers_historic[(peer_ip, peer_listening_port)] = entity
            print(f"Connected: {peer_ip}:{peer_listening_port} as {'Group' if is_group else 'Peer'}")

            # Step 9: Start a thread to handle receiving messages from the peer
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

        
    def generate_prime_modulus(self):
        # Example: generate a large prime modulus (this could be adjusted based on your requirements)
        return sslib.util.select_prime_larger_than(100000)  # Choose an appropriate range for your use case
    
    def generate_group_key(self):
        # Generate a random AES key (for encryption purposes)
        return secrets.token_bytes(32)  # AES 256-bit key
    
    def encrypt_share(self, public_key, share):
        # Encrypt share using public key
        share_bytes = bytes(share)  # Convert the share to bytes
        encrypted_share = public_key.encrypt(share_bytes, _Padding.OAEP(mgf=_Padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256()), label=None)
        return encrypted_share    
           
    def create_new_group(self):
        """
        Allows the user to create a new group with secret sharing attributes.
        """
        # 1. Collect Group Details
        group_name = simpledialog.askstring("New Group", "Enter the name of the new group:")
        if not group_name:
            return

        # Fetch the user's topics from all Firebase replicas
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        all_user_topics = set()  # Use a set to avoid duplicates
        
        for replica in self.firebase_refs:
            try:
                user_ref = db.reference(f"{replica}/users/{user_id}")
                user_data = user_ref.get()
                if user_data:
                    all_user_topics.update(user_data.get('topics', []))
            except Exception as e:
                print(f"Failed to fetch topics from replica {replica}: {e}")
                continue

        # Ensure there are topics available
        if not all_user_topics:
            messagebox.showerror("Error", "You don't have any topics defined. Please create topics first.")
            return

        # Let the user select a topic from the unified list
        topic = simpledialog.askstring(
            "Group Topic", f"Select a topic for the group (Your Topics: {', '.join(all_user_topics)})"
        )
        if not topic or topic not in all_user_topics:
            messagebox.showerror("Error", "Invalid topic selection.")
            return

        # 2. Generate Group Key and Secret Shares
        group_key = getrandbits(256)  # Random 256-bit group key
        group_key_bytes = group_key.to_bytes(32, byteorder='big')  # 32 bytes for 256 bits
        shared_data = shamir.split_secret(group_key_bytes, 2, 2)

        shares = [(user_id, bytes_to_base64(share)) for user_id, share in shared_data['shares']]
        threshold = shared_data['required_shares']
        prime_mod = bytes_to_base64(shared_data['prime_mod'])

        # 3. Store Group in Firebase
        for replica in self.firebase_refs:
            try:
                group_ref = db.reference(f"{replica}/groups/{sanitize_for_firebase_path(group_name)}")
                if group_ref.get():
                    messagebox.showerror("Error", f"Group '{group_name}' already exists.")
                    return

                group_data = {
                    'topic': topic,
                    'members': {},  # Creator's public key
                    'shares': shares,  # Convert share bytes to base64
                    'threshold': threshold,  # The required number of shares to reconstruct the secret
                    'prime_mod': prime_mod  # Convert prime_mod bytes to base64
                }
                group_ref.set(group_data)
            except Exception as e:
                print(f"Failed to create group in Firebase {replica}: {e}")
                continue

        # 4. Store Group in S3
        for s3_bucket_name in self.s3_bucket_names:
            try:
                self.create_group_in_s3(group_name, topic, shares, threshold, prime_mod, s3_bucket_name)
            except Exception as e:
                print(f"Failed to create group in S3 bucket {s3_bucket_name}: {e}")
                continue
            
        # 5. Store Group in Cosmos DB
        for cosmos_name in self.cosmos_names:
            try:
                self.create_group_in_cosmos(group_name, topic, shares, threshold, prime_mod, cosmos_name)
            except Exception as e:
                print(f"Failed to create group in Cosmos DB {cosmos_name}: {e}")
                continue

        # Confirm group creation
        messagebox.showinfo("Group Created", f"Group '{group_name}' has been created.")
        
    def create_group_in_s3(self, group_name, topic, shares, threshold, prime_mod, s3_bucket_name):
        """
        Stores the group data in AWS S3, creating a group if it doesn't exist.
        """
        group_data = {
            'group_name': group_name,
            'topic': topic,
            'shares': shares,
            'threshold': threshold,
            'prime_mod': prime_mod
        }

        # Store group data in AWS S3 (group_name as the key)
        try:
            s3_key = f"groups/{group_name}.json"
            self.s3_client.put_object(
                Bucket=s3_bucket_name,
                Key=s3_key,
                Body=json.dumps(group_data),
                ContentType='application/json'
            )
            print(f"Group '{group_name}' created in S3 with topic '{topic}' and distributed shares.")
        except Exception as e:
            print(f"Failed to create group in S3: {e}")
            
    def create_group_in_cosmos(self, group_name, topic, shares, threshold, prime_mod, cosmos_name):
        """
        Stores the group data in Cosmos DB, creating a dedicated container for the group.
        """
        try:
            # Get or create the database
            database = self.cosmos_client.create_database_if_not_exists(id=cosmos_name)

            # Dynamically create a container for the group
            container_name = f"group_{sanitize_for_firebase_path(group_name)}"
            container = database.create_container_if_not_exists(
                id=container_name,
                partition_key=PartitionKey(path="/id"),  # Use "id" as the partition key
            )

            # Group metadata
            group_data = {
                "id": "metadata",  # Identifier for the group's metadata
                "group_name": group_name,
                "topic": topic,
                "shares": shares,
                "threshold": threshold,
                "prime_mod": prime_mod,
                "members": []  # Initially empty; members can be added later
            }

            # Store the group's metadata in the container
            container.create_item(body=group_data)
            print(f"Group '{group_name}' created in Cosmos DB under container '{container_name}'.")

        except Exception as e:
            print(f"Failed to create group in Cosmos DB: {e}")

    def connect_to_group(self, group_name):
        """
        Connects to a group chat by name, ensures the user is added to the group's members,
        and checks if the user has access to the group based on topics and secret shares.
        """
        
        # Get the user's topics of interest from Firebase
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        firebase_ok = False
        s3_ok = False
        cosmos_ok = False
            
        # Step 1: Try connecting through Firebase
        try:
            print("Attempting to connect via Firebase...")
            firebase_ok = self.connect_to_group_firebase(group_name, user_id)
        except Exception as e:
            print(f"Firebase connection failed: {e}")

        try:
            print(f'Attempting to connect via S3')
            s3_ok = self.connect_to_group_s3(group_name, user_id)
        except Exception as e:
            print(f"S3 connection failed: {e}")
            
        try:
            print(f"Attempting to connect via Cosmos DB...")
            cosmos_ok = self.connect_to_group_cosmos(group_name, user_id)
        except Exception as e:
            print(f"Cosmos DB connection failed: {e}")

        # Final Step: Check if we successfully connected
        if not firebase_ok and not s3_ok and not cosmos_ok:
            messagebox.showerror("Error", f"Failed to connect to group '{group_name}' via all services.")
            return        
        
        # Proceed to connect to the group
        if group_name not in self.peers:
            # Create a ConnectionEntity for the group
            entity = ConnectionEntity.ConnectionEntity(None, None, None, None, None, is_group=True, group_name=group_name)
            self.peers[group_name] = entity
            self.peers_historic[group_name] = entity

            # Start a thread to receive messages from the group
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()

            messagebox.showinfo("Connected to Group", f"Connected to group '{group_name}'")
            self.gui_app.setup_main_menu()
        else:
            messagebox.showinfo("Info", f"Already connected to group '{group_name}'")
            
    def connect_to_group_firebase(self, group_name, user_id):
        """
        Connects to a group in Firebase, checks the user's topics, and updates the group's members.
        Returns True or False if the user cannot join the group.
        """
        
        ok = False
        
        for replica in self.firebase_refs:
            # Get the user's topics of interest from Firebase
            user_ref = db.reference(f"{replica}/users/{user_id}")
            user_data = user_ref.get()
            user_topics = user_data.get('topics', []) if user_data else []

            # Get the group's data
            group_id = sanitize_for_firebase_path(group_name)
            group_ref = db.reference(f"{replica}/groups/{group_id}")
            group_data = group_ref.get()

            if not group_data:
                continue

            group_topic = group_data.get('topic')

            # Check if the group topic matches the user's topics of interest
            if group_topic not in user_topics:
                continue

            # Retrieve members and ensure the user is added
            members = group_data.get('members', [])
            if user_id not in members:
                members.append(user_id)
                group_data['members'] = members

                # Update the members list in Firebase
                group_ref.update({'members': members})

                print(f"User {user_id} added to group '{group_name}' in Firebase.")
                
            # Ensure the group key can be reconstructed or regenerated
            if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                shares = group_data['shares']  # This is a list of (counter, share)
                threshold = group_data['threshold']
                prime_mod_base64 = group_data['prime_mod']

                # Decode the prime_mod from Base64 back to bytes
                prime_mod = base64.b64decode(prime_mod_base64)

                # Rebuild the shares list
                shares_list = []
                for counter, share_base64 in shares:
                    # Decode the shares from Base64 back to bytes
                    share_bytes = base64.b64decode(share_base64)
                    shares_list.append((counter, share_bytes))

                # Rebuild the shared_data dictionary for use in Shamir's Secret Sharing
                shared_data = {
                    'shares': shares_list,
                    'required_shares': threshold,
                    'prime_mod': prime_mod
                }

                # Attempt to recover the group key using the shares and threshold
                group_key = shamir.recover_secret(shared_data)

                if not group_key:
                    messagebox.showerror("Error", f"Failed to reconstruct group key for '{group_name}'.")
                    continue
            else:
                messagebox.showerror("Error", f"The group '{group_name}' does not have valid shares or a secret.")
                continue

            # Check if the number of members exceeds the number of shares
            if len(members) > len(shares):
                # Regenerate group key and redistribute shares
                group_key = os.urandom(32)  # Generate a new 256-bit key
                shared_data = shamir.split_secret(group_key, threshold, len(members))

                # Encode and store the new shares
                new_shares = [
                    (index, base64.b64encode(share).decode('utf-8'))
                    for index, share in shared_data['shares']
                ]
                prime_mod_base64 = base64.b64encode(shared_data['prime_mod']).decode('utf-8')                
                    
                group_ref.update({
                    'shares': new_shares,
                    'prime_mod': prime_mod_base64,
                    'threshold': threshold
                })
            ok = True
        return ok        
        
    def connect_to_group_s3(self, group_name, user_id):
        """
        Connects to a group in S3, ensures the user has access, and updates the group members.
        Returns True or False if the user cannot join the group.
        """
        ok = False
        
        for s3_bucket_name in self.s3_bucket_names:
            # Retrieve the group data from S3
            s3_key = f"groups/{group_name}.json"
            response = self.s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
            group_data = json.loads(response['Body'].read().decode('utf-8'))
            
            if not group_data:
                continue

            # Check if the user has access to the group's topic
            group_topic = group_data.get('topic')
            user_topics = self.get_user_topics_from_s3(user_id, s3_bucket_name)  # Helper function to get user topics

            if group_topic not in user_topics:
                continue

            # Ensure the user is added to the group's members
            members = group_data.get('members', [])
            if user_id not in members:
                members.append(user_id)
                group_data['members'] = members

                # Update the group data in S3
                self.s3_client.put_object(
                    Bucket=s3_bucket_name,
                    Key=s3_key,
                    Body=json.dumps(group_data)
                )
                print(f"User {user_id} added to group '{group_name}' in S3.")
                
            # Ensure the group key can be reconstructed or regenerated
            if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                shares = group_data['shares']  # This is a list of (counter, share)
                threshold = group_data['threshold']
                prime_mod_base64 = group_data['prime_mod']

                # Decode the prime_mod from Base64 back to bytes
                prime_mod = base64.b64decode(prime_mod_base64)

                # Rebuild the shares list
                shares_list = []
                for counter, share_base64 in shares:
                    # Decode the shares from Base64 back to bytes
                    share_bytes = base64.b64decode(share_base64)
                    shares_list.append((counter, share_bytes))

                # Rebuild the shared_data dictionary for use in Shamir's Secret Sharing
                shared_data = {
                    'shares': shares_list,
                    'required_shares': threshold,
                    'prime_mod': prime_mod
                }

                # Attempt to recover the group key using the shares and threshold
                group_key = shamir.recover_secret(shared_data)

                if not group_key:
                    messagebox.showerror("Error", f"Failed to reconstruct group key for '{group_name}'.")
                    continue
            else:
                messagebox.showerror("Error", f"The group '{group_name}' does not have valid shares or a secret.")
                continue

            # Check if the number of members exceeds the number of shares
            if len(members) > len(shares):
                # Regenerate group key and redistribute shares
                group_key = os.urandom(32)  # Generate a new 256-bit key
                shared_data = shamir.split_secret(group_key, threshold, len(members))

                # Encode and store the new shares
                new_shares = [
                    (index, base64.b64encode(share).decode('utf-8'))
                    for index, share in shared_data['shares']
                ]
                prime_mod_base64 = base64.b64encode(shared_data['prime_mod']).decode('utf-8')                
                
                group_data['shares'] = new_shares
                group_data['prime_mod'] = prime_mod_base64
                group_data['threshold'] = threshold
                self.s3_client.put_object(
                    Bucket=s3_bucket_name,
                    Key=s3_key,
                    Body=json.dumps(group_data)
                )                                   
            ok = True

        return ok

    def get_user_topics_from_s3(self, user_id, s3_bucket_name):
        """
        Helper function to retrieve the user's topics of interest from S3.
        """
        try:
            s3_key = f"users/{user_id}.json"
            response = self.s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
            user_data = json.loads(response['Body'].read().decode('utf-8'))
            return user_data.get('topics', [])
        except Exception as e:
            print(f"Failed to retrieve user topics from S3: {e}")
            return []
        
    def connect_to_group_cosmos(self, group_name, user_id):
        """
        Connects to a group in Cosmos DB, ensures the user has access, and updates the group members.
        Returns True or False if the user cannot join the group.
        """
        ok = False
        
        for cosmos_name in self.cosmos_names:
            # Access the Cosmos DB database and container
            database = self.cosmos_client.create_database_if_not_exists(id=cosmos_name)
            container_name = f"group_{sanitize_for_firebase_path(group_name)}"
            container = database.get_container_client(container_name)

            # Fetch the group metadata
            group_data = container.read_item(item="metadata", partition_key="metadata")
            
            if not group_data:
                continue

            # Check if the user has access to the group's topic
            group_topic = group_data.get('topic')
            user_topics = self.get_user_topics_from_cosmos(user_id, cosmos_name)  # Helper function to get user topics

            if group_topic not in user_topics:
                continue

            # Ensure the user is added to the group's members
            members = group_data.get('members', [])
            if user_id not in members:
                members.append(user_id)
                group_data['members'] = members

                # Update the group metadata in Cosmos DB
                container.upsert_item(group_data)
                print(f"User {user_id} added to Cosmos DB group '{group_name}'.")
                
            # Ensure the group key can be reconstructed or regenerated
            if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                shares = group_data['shares']  # This is a list of (counter, share)
                threshold = group_data['threshold']
                prime_mod_base64 = group_data['prime_mod']

                # Decode the prime_mod from Base64 back to bytes
                prime_mod = base64.b64decode(prime_mod_base64)

                # Rebuild the shares list
                shares_list = []
                for counter, share_base64 in shares:
                    # Decode the shares from Base64 back to bytes
                    share_bytes = base64.b64decode(share_base64)
                    shares_list.append((counter, share_bytes))

                # Rebuild the shared_data dictionary for use in Shamir's Secret Sharing
                shared_data = {
                    'shares': shares_list,
                    'required_shares': threshold,
                    'prime_mod': prime_mod
                }

                # Attempt to recover the group key using the shares and threshold
                group_key = shamir.recover_secret(shared_data)

                if not group_key:
                    messagebox.showerror("Error", f"Failed to reconstruct group key for '{group_name}'.")
                    continue
            else:
                messagebox.showerror("Error", f"The group '{group_name}' does not have valid shares or a secret.")
                continue

            # Check if the number of members exceeds the number of shares
            if len(members) > len(shares):
                # Regenerate group key and redistribute shares
                group_key = os.urandom(32)  # Generate a new 256-bit key
                shared_data = shamir.split_secret(group_key, threshold, len(members))

                # Encode and store the new shares
                new_shares = [
                    (index, base64.b64encode(share).decode('utf-8'))
                    for index, share in shared_data['shares']
                ]
                prime_mod_base64 = base64.b64encode(shared_data['prime_mod']).decode('utf-8')                
            
                group_data['shares'] = new_shares
                group_data['prime_mod'] = prime_mod_base64
                group_data['threshold'] = threshold
                container.upsert_item(group_data)
                print(f"Group '{group_name}' key regenerated and updated in Cosmos DB.")                

            ok = True
        return ok

    def get_user_topics_from_cosmos(self, user_id, cosmos_name):
        """
        Helper function to retrieve the user's topics of interest from Cosmos DB.
        """
        try:
            # Access the Cosmos DB database and container
            database = self.cosmos_client.create_database_if_not_exists(id=cosmos_name)
            container = database.get_container_client("users")

            # Retrieve the user's data
            user_data = container.read_item(item=user_id, partition_key=user_id)
            return user_data.get('topics', [])
        except Exception as e:
            print(f"Failed to retrieve user topics from Cosmos DB: {e}")
            return []
            
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

    def connect_to_peer(self, peer_ip, peer_port, already_connected=False):
        """
        Connects to a peer using the provided IP and port.
        """
        try:
            # Step 1: Create a socket and connect to the peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Step 1: Send handshake flag
            handshake_flag = "already_connected" if already_connected else "new_connection"
            sock.sendall(handshake_flag.encode())  # Send as plain text
            print(f"Sent handshake flag: {handshake_flag}")

            if already_connected:
                
                if sock.recv(4).decode() != "ACK1":
                    raise Exception("Handshake failed!")
                
                print("Received ACK1")

                # Step 4: Send this peer's port to the other peer
                sock.sendall(self.port.to_bytes(4, byteorder="big"))
                print(f"Sent own port: {self.port}")

                # Step 5: Attempt to retrieve the session AES key
                session_aes_key = self.retrieve_aes_key(peer_ip, peer_port)
                if session_aes_key is None:
                    raise Exception(f"Could not retrieve session key for {peer_ip}:{peer_port}")
                print("Retrieved session AES key")
            else:
                
                if sock.recv(4).decode() != "ACK0":
                    raise Exception("Handshake failed!")
                
                print("Received ACK0")
                
                # Step 3: Perform ECDH key exchange
                # Send this peer's public key to the other peer
                sock.sendall(self.public_key_bytes)
                print("Sent own public key")

                # Receive the other peer's public key
                peer_public_key_bytes = self.receive_all(sock)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
                print("Received peer's public key")

                # Generate the shared secret and derive the AES session key
                shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
                session_aes_key = derive_aes_key(shared_key)
                print("Generated new AES session key")

                # Step 4: Send this peer's port to the other peer
                sock.sendall(self.port.to_bytes(4, byteorder="big"))
                print(f"Sent own port: {self.port}")

            # Step 6: Send this peer's connection type and port to the other peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            msg_length = len(encrypted_info)
            sock.sendall(msg_length.to_bytes(4, byteorder="big"))
            sock.sendall(encrypted_info)
            print("Sent connection type and port info")

            # Step 7: Receive the other peer's connection type and port
            msg_length_bytes = sock.recv(4)
            if not msg_length_bytes:
                raise Exception("Connection closed by peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder="big")
            encrypted_info = self.receive_exact(sock, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            peer_connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)
            print(f"Received peer's connection type: {peer_connection_type}, port: {peer_listening_port}")

            # Step 8: Determine if the peer is a group or an individual
            is_group = (peer_connection_type == "group")

            # Step 9: Create a `ConnectionEntity` to represent the connection
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, sock, None, session_aes_key, is_group)
            self.peers[(peer_ip, peer_listening_port)] = entity
            self.peers_historic[(peer_ip, peer_listening_port)] = entity

            # Step 10: Start a thread to handle receiving messages from the peer
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            print(f"Connected to {peer_ip}:{peer_listening_port} as {'Group' if is_group else 'Peer'}")

        except Exception as e:
            print(f"Could not connect to {peer_ip}:{peer_port}\nError: {e}")
            # Remove the peer from the peers list if connection fails
            # if (peer_ip, peer_port) in self.peers:
            #     del self.peers[(peer_ip, peer_port)]
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
            # For groups, listen to messages from the cloud databases
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
                    # Save the message to the cloud databases
                    self.save_chat_to_cloud(entity, f"{entity.ip}:{entity.port}", encrypted_message.hex())

                except Exception as e:
                    print(f"Connection to {entity.ip}:{entity.port} closed: {e}")
                    entity.connection.close()
                    # Remove the peer from peers list if connection is closed
                    if (entity.ip, entity.port) in self.peers:
                        del self.peers[(entity.ip, entity.port)]  # Use tuple as key
                    break

    def listen_to_group_messages(self, group_entity):
        """
        Listens to messages from the group in the cloud databases.
        """
        processed_message_ids = set()  # Keep track of processed messages to avoid duplication

        for replica,s3_bucket,cosmos_name in zip(self.firebase_refs,self.s3_bucket_names,self.cosmos_names):
            group_id = sanitize_for_firebase_path(group_entity.group_name)
            group_ref = db.reference(f"{replica}/groups/{group_id}/messages")

            def listener(event):
                # Event listener for new messages in the group
                if event.data and event.event_type == 'put':
                    # Ensure the event is for a new message
                    if event.path != '/':
                        message_data = event.data

                        # Extract the `message_id` for deduplication
                        message_id = message_data.get('message_id') if isinstance(message_data, dict) else None
                        if not message_id or message_id in processed_message_ids:
                            return  # Skip if message is already processed

                        processed_message_ids.add(message_id)  # Mark this message as processed

                        # Decrypt the message
                        try:
                            message = self.decrypt_group_message(group_entity, message_data)
                            # Get the sender
                            sender = message_data.get('sender', '') if isinstance(message_data, dict) else ''
                            
                            # Update chat window if sender isn't the current user
                            if sender != f"{self.host}:{self.port}":
                                if group_entity.chat_window:
                                    display_message = f"{sender}: {message}" if sender else message
                                    self.gui_app.update_chat_window(group_entity, display_message)
                        except Exception as e:
                            print(f"Error decrypting message: {e}")

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
                    # Update the chat window with the sent message
                    self.gui_app.update_chat_window(entity, f"You: {message}")
                    # For groups, send the message to the cloud databases
                    encrypted_message = self.encrypt_group_message(entity, message)
                    # Convert encrypted message to hex string for JSON serialization
                    encrypted_message_hex = encrypted_message.hex()
                    
                    message_embeddings = self.get_message_embeddings(message)
                    topic_scores = self.classify_message_to_topic(message_embeddings, self.topic_embeddings)
                    
                    print("Grupo")
                    self.save_chat_to_cloud(entity, f"{self.host}:{self.port}", encrypted_message_hex, topic_scores)
                else:
                    # Update the chat window with the sent message
                    self.gui_app.update_chat_window(entity, f"You: {message}")
                    # For peers, send the message directly over the socket
                    encrypted_message = self.encrypt_message(message, entity.aes_key)
                    encrypted_message_hex = encrypted_message.hex()
                    msg_length = len(encrypted_message)
                    entity.connection.sendall(msg_length.to_bytes(4, byteorder='big'))
                    entity.connection.sendall(encrypted_message)
                    
                    message_embeddings = self.get_message_embeddings(message)
                    topic_scores = self.classify_message_to_topic(message_embeddings, self.topic_embeddings)
                    
                    print("Sent message")
                    self.save_chat_to_cloud(entity, f"You", encrypted_message_hex, topic_scores)
                    print("AFTER")

            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")

    def save_chat_to_cloud(self, entity, sender, message, topic_scores=None):
        """
        Saves the conversation to multiple cloud databases.
        """
        timestamp = time.time()  # Current time in seconds since the epoch
        message_id = str(uuid.uuid4())  # Generate a unique message ID
        data = {'sender': sender, 'message': message, 'timestamp': timestamp, 'message_id': message_id}

            
        for replica, s3_bucket_name, cosmos_name in zip(self.firebase_refs, self.s3_bucket_names, self.cosmos_names):
        
            if entity.is_group:
            
                # Save to Firebase
                group_id = sanitize_for_firebase_path(entity.group_name)
                group_ref = db.reference(f"{replica}/groups/{group_id}/messages")
                group_ref.child(message_id).set(data)  # Use message_id as key
                #Save to AWS S3
                self.save_to_aws_s3(f"groups/{group_id}/messages/{message_id}.json", data, s3_bucket_name)
                self.save_to_cosmos(group_id, data, cosmos_name, True)
            else:
                # Save to Firebase
                chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
                chat_ref = db.reference(f"{replica}/chats/{chat_id}")
                chat_ref.child(message_id).set(data)
                # Save to AWS S3
                self.save_to_aws_s3(f"chats/{chat_id}/{message_id}.json", data, s3_bucket_name)
                self.save_to_cosmos(chat_id, data, cosmos_name, False)

            if not topic_scores == None:
                local_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
                topic_scores_ref = db.reference(f"{replica}/users/{local_id}/topic_scores")
                scores_in_db = topic_scores_ref.get()
                
                if isinstance(scores_in_db, list):
                    for i in range(len(topic_scores)):
                        scores_in_db[i] += topic_scores[i]
                    topic_scores_ref.set(scores_in_db)
                else:
                    topic_scores_ref.set(topic_scores)                
                
                
    def save_to_aws_s3(self, path, data, s3_bucket_name):
        """
        Saves data to AWS S3 in JSON format.
        """
        key = f"{path}/{secrets.token_hex(16)}.json"
        # Ensure that data is JSON serializable
        json_data = json.dumps(data)
        self.s3_client.put_object(
            Bucket=s3_bucket_name,
            Key=key,
            Body=json_data
        )
        
    def save_to_cosmos(self, chat_id, data, cosmos_name, is_group):
        """
        Saves chat messages to a Cosmos DB container dynamically created for each chat.
        """
        try:
            # Get or create the database
            database = self.cosmos_client.create_database_if_not_exists(id=cosmos_name)

            # Dynamically create a container for the chat or group
            container_name = f"group_{chat_id}" if is_group else f"chat_{chat_id}"
            
            container = database.create_container_if_not_exists(
                id=container_name,
                partition_key=PartitionKey(path="/id"),  # Use message_id as the partition key
            )
            
            # Ensure the data has an "id" field matching the partition key
            data['id'] = data.get('message_id', f"default-{uuid.uuid4()}")  # Use message_id or fallback

            # Insert or update the message data in the container
            container.create_item(body=data)
        except Exception as e:
            print(f"Error saving message to Cosmos DB: {e}")

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
    
    def encrypt_group_message(self, group_entity, message):
        """
        Encrypts a message for a group using its AES group key.
        """
        group_key_hex = self.get_group_key(group_entity)
        group_key = bytes.fromhex(group_key_hex)  # Convert hex to bytes

        # Generate a nonce for AES-GCM
        nonce = os.urandom(12)

        # Encrypt the message
        encryptor = Cipher(
            algorithms.AES(group_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

        # Combine nonce, ciphertext, and tag
        encrypted_message = nonce + ciphertext + encryptor.tag
        return encrypted_message
    
    def decrypt_group_message(self, group_entity, encrypted_message_data):
        """
        Decrypts a group message using the group's AES encryption key.
        """
        try:
            # Retrieve the group key
            group_key_hex = self.get_group_key(group_entity)
            group_key = bytes.fromhex(group_key_hex)

            # Extract the encrypted message from the data
            if isinstance(encrypted_message_data, dict):
                encrypted_message_hex = encrypted_message_data.get('message', '')
            elif isinstance(encrypted_message_data, str):
                encrypted_message_hex = encrypted_message_data
            else:
                print(f"Unknown encrypted_message_data type: {type(encrypted_message_data)}")
                return "[Unable to decrypt message]"

            # Decode the encrypted message
            encrypted_message = bytes.fromhex(encrypted_message_hex)

            # Extract nonce, ciphertext, and tag
            nonce = encrypted_message[:12]
            tag = encrypted_message[-16:]
            ciphertext = encrypted_message[12:-16]

            # Decrypt the message
            decryptor = Cipher(
                algorithms.AES(group_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            ).decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode('utf-8')

        except Exception as e:
            print(f"Decryption failed: {e}")
            return "[Unable to decrypt message]"
        
    def get_group_key(self, group_entity):
        """
        Retrieves or reconstructs the group key using Shamir's Secret Sharing.
        """
        
        found = False
        
        for replica in self.firebase_refs:
        
            group_id = sanitize_for_firebase_path(group_entity.group_name)
            group_ref = db.reference(f"{replica}/groups/{group_id}")
            group_data = group_ref.get()

            # Reconstruct the key using SSS if shares are present
            if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                shares = group_data['shares']  # [(member_id, share_base64)]
                threshold = group_data['threshold']
                prime_mod = base64.b64decode(group_data['prime_mod'])

                # Decode shares from Base64
                decoded_shares = [(int(member_id), base64.b64decode(share_base64)) for member_id, share_base64 in shares]

                # Ensure we have at least the required number of shares
                if len(decoded_shares) < threshold:
                    raise ValueError(f"Not enough shares to reconstruct the key for '{group_entity.group_name}'.")

                # Use SSS to reconstruct the group key
                reconstructed_key = shamir.recover_secret({
                    "shares": decoded_shares[:threshold],
                    "prime_mod": prime_mod,
                    "required_shares": threshold
                })

                # Store the reconstructed key back in Firebase for future use
                group_key_hex = reconstructed_key.hex()
                group_ref.update({"group_key": group_key_hex})
                found = True
                return group_key_hex

            raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}'.")
        
        if not found:
            
            # Do the same for S3
            for s3_bucket_name in self.s3_bucket_names:
                try:
                    s3_key = f"groups/{group_entity.group_name}.json"
                    response = self.s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
                    group_data = json.loads(response['Body'].read().decode('utf-8'))

                    # Reconstruct the key using SSS if shares are present
                    if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                        shares = group_data['shares']  # [(member_id, share_base64)]
                        threshold = group_data['threshold']
                        prime_mod = base64.b64decode(group_data['prime_mod'])

                        # Decode shares from Base64
                        decoded_shares = [(int(member_id), base64.b64decode(share_base64)) for member_id, share_base64 in shares]

                        # Ensure we have at least the required number of shares
                        if len(decoded_shares) < threshold:
                            raise ValueError(f"Not enough shares to reconstruct the key for '{group_entity.group_name}'.")

                        # Use SSS to reconstruct the group key
                        reconstructed_key = shamir.recover_secret({
                            "shares": decoded_shares[:threshold],
                            "prime_mod": prime_mod,
                            "required_shares": threshold
                        })

                        # Store the reconstructed key back in S3 for future use
                        group_key_hex = reconstructed_key.hex()
                        group_data['group_key'] = group_key_hex
                        self.s3_client.put_object(
                            Bucket=s3_bucket_name,
                            Key=s3_key,
                            Body=json.dumps(group_data),
                            ContentType='application/json'
                        )
                        found = True
                        return group_key_hex

                    raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}' in S3.")
                except Exception as e:
                    print(f"Failed to retrieve or reconstruct group key in S3: {e}")
                    raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}' in S3.")
                
        if not found:
            # Do the same for Cosmos DB
            for cosmos_name in self.cosmos_names:
                try:
                    # Get the group data from Cosmos DB
                    database = self.cosmos_client.get_database_client(cosmos_name)
                    container = database.get_container_client(f"group_{sanitize_for_firebase_path(group_entity.group_name)}")
                    group_data = container.read_item(item="metadata", partition_key="metadata")
                    
                    if 'shares' in group_data and 'threshold' in group_data and 'prime_mod' in group_data:
                        shares = group_data['shares']
                        threshold = group_data['threshold']
                        prime_mod = base64.b64decode(group_data['prime_mod'])
                        
                        # Decode shares from Base64
                        decoded_shares = [(int(member_id), base64.b64decode(share_base64)) for member_id, share_base64 in shares]
                        
                        if len(decoded_shares) < threshold:
                            raise ValueError(f"Not enough shares to reconstruct the key for '{group_entity.group_name}' in Cosmos DB.")
                        
                        # Use SSS to reconstruct the group key
                        reconstructed_key = shamir.recover_secret({
                            "shares": decoded_shares[:threshold],
                            "prime_mod": prime_mod,
                            "required_shares": threshold
                        })
                        
                        # Store the reconstructed key back in Cosmos DB for future use
                        group_key_hex = reconstructed_key.hex()
                        group_data['group_key'] = group_key_hex
                        container.upsert_item(group_data)
                        found = True
                        return group_key_hex
                    
                    raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}' in Cosmos DB.")
                except Exception as e:
                    print(f"Failed to retrieve or reconstruct group key in Cosmos DB: {e}")
                    raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}' in Cosmos DB.")
                
        if not found:
            raise ValueError(f"Unable to retrieve or reconstruct the group key for '{group_entity.group_name}'.")
            
        return None
   

    def save_topics(self):
        """
        Saves the user's selected topics to Firebase and handles the 'None' placeholder appropriately.
        """
        selected_topics = [topic for topic, var in self.gui_app.topic_vars.items() if var.get() == 1]
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        
        for replica in self.firebase_refs:
        
            user_ref = db.reference(f"{replica}/users/{user_id}")
            user_data = user_ref.get()

            if selected_topics:

                if user_data and 'topics' in user_data and 'None' in user_data['topics']:
                    current_topics = [topic for topic in user_data['topics'] if topic != 'None']
                    current_topics.extend(selected_topics)

                    user_ref.update({'topics': list(set(current_topics))})
                else:
                    # Just update with selected topics if 'None' isn't present
                    user_ref.update({'topics': selected_topics})
                print("Topics saved:", selected_topics)
            else:
                # If no topics are selected, add 'None' to keep the user entry alive in the database
                user_ref.update({'topics': ['None']})
                print("No topics selected, placeholder 'None' added.")
            
            
        for s3_bucket_name,cosmos_name in zip(self.s3_bucket_names, self.cosmos_names):
            
            # After saving to Firebase, also save to AWS S3
            self.update_user_topics_in_s3(user_id, selected_topics, s3_bucket_name)            
            self.update_user_topics_in_cosmos(user_id, selected_topics, cosmos_name)

        # Verify if the user's groups topics that he is in are the same as the topics that he has,
        # in case he is in a group that has a topic that the user doesn't have then the connection with that group is closed
        user_groups = [group for group in self.peers if group != 'You' and self.peers[group].is_group]
        for group in user_groups:
            for replica in self.firebase_refs:
                group_ref = db.reference(f"{replica}/groups/{sanitize_for_firebase_path(group)}")
                group_data = group_ref.get()
                if group_data:
                    group_topic = group_data.get('topic')
                    if group_topic not in selected_topics:
                        print(f"Closing connection with group '{group}' as it is in topic '{group_topic}' that you don't have anymore.")
                        self.remove_user_from_group(group, user_id)
                        del self.peers[group]
                        del self.peers_historic[group]
                        break

        messagebox.showinfo("Topics Saved", "Your topics of interest have been saved.")
        self.gui_app.setup_main_menu()
        
    def update_user_topics_in_s3(self, user_id, selected_topics, s3_bucket_name):
        """
        Updates only the user's topics in AWS S3.
        """
        try:
            # Fetch the existing user data from S3
            s3_key = f"users/{user_id}.json"
            response = self.s3_client.get_object(Bucket=s3_bucket_name, Key=s3_key)
            user_data = json.loads(response['Body'].read().decode('utf-8'))

            # Update the topics in the user data
            user_data['topics'] = selected_topics

            # Write the updated user data back to S3
            self.s3_client.put_object(
                Bucket=s3_bucket_name,
                Key=s3_key,
                Body=json.dumps(user_data),
                ContentType='application/json'
            )
            print(f"User topics for '{user_id}' successfully updated in S3.")
        except Exception as e:
            print(f"Failed to update user topics in S3: {e}")
            
    def update_user_topics_in_cosmos(self, user_id, selected_topics, cosmos_db_name):
        """
        Updates the user's topics in the Cosmos DB database.
        """
        try:
            # Get Cosmos database and container
            database = self.cosmos_client.get_database_client(cosmos_db_name)
            container = database.get_container_client("users")

            user_doc = container.read_item(item=user_id, partition_key=user_id)
            user_doc.update({'topics': selected_topics})

            # Update the user document in Cosmos DB
            container.replace_item(item=user_doc['id'], body=user_doc)
            print(f"Topics updated in Cosmos DB {cosmos_db_name} for user {user_id}: {user_doc['topics']}")
            
        except Exception as e:
            print(f"Error updating topics in Cosmos DB {cosmos_db_name} for user {user_id}: {e}")
    
    def remove_user_from_group(self, group_name, user_id):
        """
        Removes the user from the group in all cloud services.
        """
        # Remove the user from Firebase group members
        for replica in self.firebase_refs:
            # Get the reference to the group's members list
            group_members_ref = db.reference(f"{replica}/groups/{sanitize_for_firebase_path(group_name)}")
            
            group_data = group_members_ref.get()
            
            try:
                # Update the members list
                if "members" in group_data:
                    members = [member for member in group_data["members"] if member != user_id]
                    
                group_members_ref.update({'members': members})
                
            except Exception as e:
                print(f"Error removing user from Firebase group '{group_name}': {e}")

        # You can optionally add S3 and Cosmos DB updates here as you originally had.

        # Update AWS S3
        for bucket_name in self.s3_bucket_names:
            try:
                # Fetch the current group data
                group_path = f"groups/{group_name}.json"
                response = self.s3_client.get_object(Bucket=bucket_name, Key=group_path)
                group_data = json.loads(response['Body'].read().decode('utf-8'))

                # Update the members list
                if "members" in group_data:
                    group_data["members"] = [member for member in group_data["members"] if member != user_id]

                # Save the updated group data back to S3
                self.s3_client.put_object(
                    Bucket=bucket_name,
                    Key=group_path,
                    Body=json.dumps(group_data)
                )
                print(f"Updated members for S3 group '{group_name}'.")

            except Exception as e:
                print(f"Error updating user in S3 group '{group_name}': {e}")

        # Update Cosmos DB
        for cosmos_name in self.cosmos_names:
            try:
                # Fetch the group document
                container = self.cosmos_client.get_database_client(cosmos_name).get_container_client("group_"+group_name)
                group_data = container.read_item(item="metadata", partition_key="metadata")

                # Update the members list
                if "members" in group_data:
                    group_data["members"] = [member for member in group_data["members"] if member != user_id]

                # Replace the updated document in Cosmos DB
                container.replace_item(item="metadata", body=group_data)
                print(f"Updated members for Cosmos DB group '{group_name}'.")

            except Exception as e:
                print(f"Error updating user in Cosmos DB group '{group_name}': {e}")


    def load_messages_from_cloud(self, entity):
        """
        Loads messages from multiple cloud databases, decrypts them, and sorts them by timestamp.
        """
        messages = []
        seen_message_ids = set()
        message_objects = []  # Collect message objects with timestamp for sorting

        if entity.is_group:
            # Firebase
            for replica in self.firebase_refs:
                group_id = sanitize_for_firebase_path(entity.group_name)
                group_ref = db.reference(f"{replica}/groups/{group_id}/messages")
                messages_data = group_ref.get() or {}

                if messages_data:
                    for msg_id, message_data in messages_data.items():
                        if msg_id in seen_message_ids:
                            continue
                        seen_message_ids.add(msg_id)  # Mark message as seen

                        try:
                            # Decrypt message
                            sender = message_data.get('sender', '')
                            if sender == f"{self.host}:{self.port}":
                                sender = "You"
                            message = self.decrypt_group_message(entity, message_data)
                            timestamp = message_data.get('timestamp', 0)  # Default to 0 if timestamp is missing
                            display_message = f"{sender}: {message}" if sender else message

                            # Add to message objects with timestamp
                            message_objects.append({"message": display_message, "timestamp": timestamp})
                        except Exception as e:
                            print(f"Error decrypting Firebase message: {e}")
                            continue  # Skip to the next message
                        
            # AWS S3
            for bucket_name in self.s3_bucket_names:
                try:
                    # Define the group folder path
                    group_folder_path = f"groups/{entity.group_name}/"

                    # List all objects in the group folder
                    response = self.s3_client.list_objects_v2(Bucket=bucket_name, Prefix=group_folder_path)

                    # Check if there are objects (messages) in the folder
                    if 'Contents' in response:
                        for obj in response['Contents']:
                            file_key = obj['Key']
                            
                            # Skip non-message files (like metadata or folder keys)
                            if file_key.endswith('/'):
                                continue

                            # Fetch the individual message file
                            try:
                                message_response = self.s3_client.get_object(Bucket=bucket_name, Key=file_key)
                                message_data = json.loads(message_response['Body'].read().decode('utf-8'))

                                # Process the message
                                msg_id = message_data.get('message_id')
                                if msg_id in seen_message_ids:
                                    continue
                                seen_message_ids.add(msg_id)  # Mark message as seen

                                try:
                                    # Decrypt message
                                    sender = message_data.get('sender', '')
                                    if sender == f"{self.host}:{self.port}":
                                        sender = "You"
                                    message = self.decrypt_group_message(entity, message_data)
                                    timestamp = message_data.get('timestamp', 0)  # Default to 0 if timestamp is missing
                                    display_message = f"{sender}: {message}" if sender else message

                                    # Add to message objects with timestamp
                                    message_objects.append({"message": display_message, "timestamp": timestamp})
                                except Exception as e:
                                    print(f"Error decrypting S3 message: {e}")
                                    continue  # Skip to the next message

                            except Exception as e:
                                print(f"Error fetching message '{file_key}' from S3 bucket '{bucket_name}': {e}")

                except Exception as e:
                    print(f"Error listing messages in S3 bucket '{bucket_name}' group folder: {e}")


            # Inside load_messages_from_cloud function
            # Add this block to process Cosmos DB messages

            for cosmos_name in self.cosmos_names:
                try:
                    # Access the Cosmos DB container for the group
                    container = self.cosmos_client.get_database_client(cosmos_name).get_container_client(f"group_{entity.group_name}")

                    # Query all items in the container
                    query_result = container.query_items(
                        query="SELECT * FROM c",  # Simple query to fetch all items
                        enable_cross_partition_query=True  # Enable cross-partition query if needed
                    )

                    # Process each item
                    for item in query_result:
                        # Skip metadata items (e.g., look for a distinguishing property like 'type')
                        if item.get('type') == 'metadata' or item.get('id') in seen_message_ids:
                            continue

                        seen_message_ids.add(item.get('id'))  # Mark as seen
                        
                        if item.get('type') != 'metadata' and item.get('id') not in seen_message_ids:

                            try:
                                # Decrypt the message
                                sender = item.get('sender', '')
                                if sender == f"{self.host}:{self.port}":
                                    sender = "You"
                                message = self.decrypt_group_message(entity, item)
                                timestamp = item.get('timestamp', 0)  # Default to 0 if missing
                                display_message = f"{sender}: {message}" if sender else message

                                # Add to the message objects for sorting
                                message_objects.append({"message": display_message, "timestamp": timestamp})
                            except Exception as e:
                                print(f"Error decrypting Cosmos DB message: {e}")
                                continue  # Skip to the next message

                except Exception as e:
                    print(f"Error fetching messages from Cosmos DB database '{cosmos_name}': {e}")

        else: 
            
            local_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
            remote_id = f"{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_id = f"{local_id}_{remote_id}"
            chat_path = f"chats/{chat_id}.json"
            
            for replica in self.firebase_refs:
                chat_ref = db.reference(f"{replica}/chats/{chat_id}")
                messages_data = chat_ref.get() or {}

                if messages_data:
                    for msg_id, message_data in messages_data.items():
                        if msg_id in seen_message_ids:
                            continue  # Skip duplicate message
                        seen_message_ids.add(msg_id)  # Mark message as seen

                        try:
                            # Decrypt message
                            sender = message_data.get('sender', '')
                            encrypted_message_bytes = bytes.fromhex(message_data['message'])
                            message = self.decrypt_message(encrypted_message_bytes, entity.aes_key)
                            timestamp = message_data.get('timestamp', 0)  # Default to 0 if timestamp is missing
                            display_message = f"{sender}: {message}" if sender else message

                            # Add to message objects with timestamp
                            message_objects.append({"message": display_message, "timestamp": timestamp})
                        except Exception as e:
                            print(f"Error decrypting message: {e}")
                            continue     
                        
                        
           # AWS S3
            for bucket_name in self.s3_bucket_names:               
            
                
                response = self.s3_client.list_objects_v2(Bucket=bucket_name, Prefix=chat_path)
                
                if 'Contents' not in response:  # If there are no objects with the given prefix
                    print(f"No chats found for path '{chat_path}' in bucket '{bucket_name}'. Skipping.")
                    continue   
                response = self.s3_client.get_object(Bucket=bucket_name, Key=chat_path)
                chat_data = json.loads(response['Body'].read().decode('utf-8')) or {}

                if "messages" in chat_data:
                    for message_data in chat_data["messages"]:
                        msg_id = message_data.get('message_id')
                        if msg_id in seen_message_ids:
                            continue
                        seen_message_ids.add(msg_id)  # Mark message as seen

                        try:
                            # Decrypt message
                            sender = message_data.get('sender', '')
                            encrypted_message_bytes = bytes.fromhex(message_data['message'])
                            message = self.decrypt_message(encrypted_message_bytes, entity.aes_key)
                            timestamp = message_data.get('timestamp', 0)  # Default to 0 if timestamp is missing
                            display_message = f"{sender}: {message}" if sender else message

                            # Add to message objects with timestamp
                            message_objects.append({"message": display_message, "timestamp": timestamp})
                        except Exception as e:
                            print(f"Error decrypting message: {e}")
                            continue 

            # Add this block to process Cosmos DB messages
            for cosmos_name in self.cosmos_names:
                try:
                    local_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
                    remote_id = f"{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
                    chat_id = f"{local_id}_{remote_id}"
                               
                    container_id = f"chat_{chat_id}"
                    database_client = self.cosmos_client.get_database_client(cosmos_name)
                        
                    if container_id not in [container['id'] for container in database_client.list_containers()]:
                        print(f"Container '{container_id}' does not exist in Cosmos DB. Skipping.")
                        continue                    
                              
                    # Access the Cosmos DB container for the group
                    container = database_client.get_container_client(container_id)

                    # Query all items in the container
                    query_result = container.query_items(
                        query="SELECT * FROM c",  # Simple query to fetch all items
                        enable_cross_partition_query=True  # Enable cross-partition query if needed
                    )

                    # Process each item
                    for item in query_result:
                        # Skip metadata items (e.g., look for a distinguishing property like 'type')
                        if item.get('type') == 'metadata' or item.get('id') in seen_message_ids:
                            continue

                        seen_message_ids.add(item.get('id'))  # Mark as seen
                        
                        if item.get('type') != 'metadata' and item.get('id') not in seen_message_ids:

                            try:
                                # Decrypt message
                                sender = message_data.get('sender', '')
                                encrypted_message_bytes = bytes.fromhex(message_data['message'])
                                message = self.decrypt_message(encrypted_message_bytes, entity.aes_key)
                                timestamp = message_data.get('timestamp', 0)  # Default to 0 if timestamp is missing
                                display_message = f"{sender}: {message}" if sender else message

                                # Add to message objects with timestamp
                                message_objects.append({"message": display_message, "timestamp": timestamp})
                            except Exception as e:
                                print(f"Error decrypting message: {e}")
                                continue 

                except Exception as e:
                    print(f"Error fetching messages from Cosmos DB database '{cosmos_name}': {e}")                                  

        # Sort messages by timestamp
        sorted_message_objects = sorted(message_objects, key=lambda x: x['timestamp'])

        # Extract only the message text for display
        messages = [obj['message'] for obj in sorted_message_objects]

        return messages

    def perform_privacy_preserving_search(self, keywords):
        """
        Searches all connected peers/groups for messages containing any of the provided keywords using ORAM.
        Supports multiple keywords and ensures privacy-preserving access patterns.
        """
        results = set()  # Use a set to avoid duplicate results

        # Ensure messages are loaded into memory
        self.load_all_messages()

        print("Starting privacy-preserving search...")
        for entity_key, entity in self.peers.items():
            if entity.messages:

                # Simulate ORAM by shuffling the messages
                import random
                random.shuffle(entity.messages)

                # Iterate over messages and match against any keyword
                for msg in entity.messages:
                    message = msg['message']

                    # Match any keyword (logical OR)
                    if any(keyword.lower() in message.lower() for keyword in keywords):
                        if entity.is_group:
                            results.add(f"Group '{entity.group_name}', Message: {message}")
                        else:
                            results.add(f"Peer {entity.ip}:{entity.port}, Message: {message}")
                    else:
                        # Dummy operation for ORAM simulation
                        pass  # Perform a no-op to simulate access for non-matching messages

        # Return results as a sorted list for consistency
        sorted_results = sorted(results)
        return sorted_results


    def load_all_messages(self):
        """
        Loads messages from all connected peers and groups into memory.
        """

        for entity_key, entity in self.peers_historic.items():
            entity.messages = []
            messages = self.load_messages_from_cloud(entity)
            
            if messages:
                for message in messages:
                    if message.startswith("You:"):
                        host_port = "You"
                        msg = message.split(":", maxsplit=1)[1].strip()  # Divide apenas no primeiro ':'
                    else:
                        # Presume que é um host:port
                        parts = message.split(":", maxsplit=2)
                        host_port = ":".join(parts[0:2])  # Junta as duas primeiras partes
                        msg = parts[2].strip()       # A terceira parte é a mensagem
                    entity.messages.append({'sender': host_port, 'message': msg})

        #self.messages_loaded = True  # Set the flag to indicate messages are loaded

    def load_ad_embeddings(self):
        # Load ads from Firebase
        ads_ref = db.reference(f"ads")
        ads_data = ads_ref.get()
        
        return ads_data

    def get_recommendations(self):
        """
        Analyzes the client's own message history to determine recommended topics and groups.
        """
            
        #Ir buscar topic_scores à base de dados
        local_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        
        #for replica, s3_bucket_name in zip(self.firebase_refs, self.s3_bucket_names):
        for replica in self.firebase_refs:
            topic_scores = db.reference(f"{replica}/users/{local_id}/topic_scores").get()
            break
        
        topics = list(self.topic_embeddings.keys())
        
        #Encontrar os dois maiores índices e valores correspondentes
        sorted_indices = sorted(range(len(topic_scores)), key=lambda i: topic_scores[i], reverse=True)
        top_indices = sorted_indices[:2]  # Pegar os dois maiores índices
        
        #Obter os tópicos correspondentes aos maiores índices
        top_two_topics = [topics[i] for i in top_indices]
        print(top_two_topics)
        
        # Step 4: Fetch ads from Firebase and generate mappings
        ads = self.fetch_ads_from_database()  # Fetch ads from Firebase

        #topic_to_ads_map, ads_embeddings = self.generate_topic_to_ads_map(ads)  # Map ads to topics
        oram = ORAM.InMemoryORAM(ads)  # Initialize ORAM-like storage
        
        # Step 5: Retrieve ads related to the top two topics
        recommendations = self.fetch_ads_for_topics(
            oram,
            [topic for topic in top_two_topics],  # Top two topics identified
            ads
        )

        # Step 6: Return the matching ads for the top topics
        return recommendations
    
    def get_message_embeddings(self, message):
        """
        Convert messages into embeddings.
        """
        return model.encode(message)   #Encode all messages to get embeddings
    
    def generate_topic_embeddings(self):
        """
        Gera embeddings representativos para cada tópico usando descrições.
        """
        topic_descriptions = {
            'Cars': "vehicles, cars, automobiles, driving, race",
            'Music': "songs, albums, bands, artists, sing, singer",
            'Soccer': "football, soccer, goals, matches, players, ball",
            'Basketball': "basketball, NBA, hoops, dunks, players, ball",
            'Cybersecurity': "cybersecurity, hacking, security, malware, encryption",
            'AI-Artificial Intelligence': "artificial intelligence, machine learning, neural networks",
            'IoT-Internet of Things': "internet of Things, smart devices, sensors, connectivity"
        }
        
        topic_embeddings = {}
        for topic, description in topic_descriptions.items():
            topic_embeddings[topic] = model.encode(description)  # Gerar embeddings para cada tópico
        
        return topic_embeddings
    
    def classify_message_to_topic(self, user_embedding, topic_embeddings):
        """
        Classifies the top two topics based on user embeddings.
        We use keyword matching here as a basic approach.
        """        
        topic_scores = {topic: 0 for topic in topic_embeddings}

        for topic, topic_emb in topic_embeddings.items():
            # Calcular a similaridade de cosseno
            similarity = cosine_similarity(
                user_embedding.reshape(1, -1), topic_emb.reshape(1, -1)
            )[0][0]
            topic_scores[topic] += similarity
            
        # Ordenar os itens do dicionário pelos valores em ordem crescente
        sorted_items = sorted(topic_scores.items(), key=lambda x: x[1])
        
        # Criar um dicionário que mapeia o valor original para o ranking
        rankings = {item[0]: rank for rank, item in enumerate(sorted_items, start=1)}
        
        # Mapear os rankings aos valores originais do dicionário
        topics_values = [rankings[key] for key in topic_scores]

        # Ordenar os tópicos com base na soma das similaridades
        return topics_values

    def fetch_ads_from_database(self):
        """
        Fetch ads from Firebase. Each ad includes a topic and text.
        """
        # Reference the 'ads' path in Firebase
        ads_ref = db.reference("ads")
        
        # Retrieve all ads as a list
        ads_data = ads_ref.get()

        if not ads_data:
            print("No ads found in the database.")
            return []

        return ads_data
    
    def generate_topic_to_ads_map(self, ads):
        """
        Generate a topic-to-ads mapping dynamically based on ads retrieved from the database.
        """
        topic_to_ads_map = {}
        ads_embeddings = []

        for idx, ad in enumerate(ads):
            topic = ad['topic']
            embedding = ad['embedding']

            # Add embedding to the ORAM storage
            ads_embeddings.append(embedding)

            # Update the mapping
            if topic not in topic_to_ads_map:
                topic_to_ads_map[idx] = []
            topic_to_ads_map[idx].append(topic)

        return topic_to_ads_map, ads_embeddings
    
    def fetch_ads_for_topics(self, oram, topics, topic_to_ads_map):
        """
        Retrieve ads related to the user's top topics.
        """
        recommendations = []

        for topic in topics:
            for idx, (ad_id, ad_content) in enumerate(topic_to_ads_map.items()):
                if ad_content['topic'] == topic:

                    ad = oram.access(idx)  # Mimic ORAM access
                    recommendations.append(ad)

        return recommendations

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
