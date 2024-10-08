from email import message
import socket
import threading
import os
import tkinter as tk

from p2pchatapp import P2PChatApp


class Peer:
    def __init__(self, host, port):
        self.host = host    # Initialize host
        self.port = port    # Initialize port
        
        self.contactsListFile = "contacts.txt"
        
        self.message = None
        self.hostToMsg = None
        self.portToMsg = None
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP SOCKET
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Permite reutilizar o endereço
        self.connections = {}  # Store active connections
        self.folder_path = str(self.host) +"_"+ str(self.port)
        
        if not os.path.exists(self.folder_path):
            os.mkdir(self.folder_path)
            print(f"Folder '{self.folder_path}' created.")

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
            
            historicConversation = self.folder_path + "/" + str(host) +"_"+ str(port) + ".txt"
            if not os.path.exists(historicConversation):
                open(historicConversation, "x")
                print(f"File '{historicConversation}' created.")
                
            contactsListPath = self.folder_path + "/" + self.contactsListFile
            if not os.path.exists(contactsListPath):
                open(contactsListPath, "a").write(str(host) +"_"+ str(port) + "-" + name + "\n")
                
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}")

    def listen(self):
        """Listen for incoming connections."""
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")

        while True:
            try:
                connection, address = self.socket.accept()
                name = f"{address[0]}:{address[1]}"
                self.connections[name] = {'socket': connection}
                threading.Thread(target=self.handle_client, args=(connection, name)).start()
            except OSError as e:
                print(f"Socket error: {e}")
                break

    def write_message_to_file(self, file_name, message):
        """Write a message to a specified file."""
        try:
            with open(f"{self.folder_path}/{file_name}", "a") as f:
                f.write(message + "\n")
        except Exception as e:
            print(f"Error writing to file: {e}")

    def send_data(self, name, message):
        """Send plaintext data."""
        try:
            connection_info = self.connections[name]
            self.hostToMsg, self.portToMsg = connection_info.get('address')

            # Prepare the message along with the host and port info
            host_port = f"{self.host}_{self.port}"
            full_message = message.encode() + b'|' + host_port.encode()

            # Check if the socket is still open
            if connection_info['socket'].send(full_message):
                # Write message to file
                self.write_message_to_file(f"{self.host}_{self.port}.txt", f"You: {message}")
            else:
                print(f"Failed to send message to {name}: Socket not open.")
        except Exception as e:
            print(f"Failed to send message: {e}")



    def handle_client(self, connection, name):
        """Handle incoming messages from a client."""
        #client_name = f"{address[0]}:{address[1]}"  # Identifying the client by its address (host:port)
        while True:
            try:
                # Receiving the message
                data = connection.recv(1024)
                if not data:
                    break
                
                # Split message and host_port
                message, host_port = data.decode().split('|')
                
                print(f"\nReceived data from {name}: {message}")
                
                # Extract host and port
                host, port = host_port.split("_")
                
                with open(self.folder_path + "/" + f"{host}_{port}.txt", "a") as f:
                    f.write(f"{host}:{port}: {message}\n")
                
                # Prepare contact info
                contact_info = f"{host}_{port}-{host}:{port}\n"

                # Update contact list safely
                contactsListPath = self.folder_path + "/" + self.contactsListFile
                try:
                    with open(contactsListPath, "r") as file:
                        if contact_info not in file.read():
                            with open(contactsListPath, "a") as append_file:
                                append_file.write(contact_info)
                except IOError as e:
                    print(f"Failed to read contact list: {e}")
                
                # Verifica se a janela de chat existe
                if name in self.connections and 'chat_window' in self.connections[name]:
                    chat_window = self.connections[name]['chat_window']
                    self.notify_chat_window(chat_window, message)  # Atualiza a janela de chat
                else:
                    print(f"No chat window for client: {name}")  # Se não houver janela

            except ValueError as e:
                print(f"ValueError in message handling: {e}")
                break
            except socket.error as e:
                print(f"Socket error: {e}")
                break

        # Remove the client from active connections when they disconnect
        del self.connections[name]
        connection.close()


    def notify_chat_window(self, client_name, message):
        """Notify the chat window of the received message."""
        if client_name in self.connections:
            connection_info = self.connections[client_name]
             # Get the chat window (chat_log) for the client
            chat_window = connection_info.get('chat_window')
            
            if chat_window:
                # If the chat window exists, display the message there
                chat_window.config(state=tk.NORMAL)
                chat_window.insert(tk.END, f"{client_name}: {message}\n")
                chat_window.config(state=tk.DISABLED)
                # Scroll to the end to show the latest message
                chat_window.see(tk.END)
            else:
                print(f"No chat window for client: {client_name}")
        else:
            print(f"Client {client_name} is not connected.")   

    def start(self):
        """Start listening for connections."""
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

    def get_connected_clients(self):
        """Return a list of connected clients."""
        return [(name, info['address'][0], info['address'][1]) for name, info in self.connections.items() if 'address' in info]
