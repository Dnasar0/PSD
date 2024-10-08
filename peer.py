import socket
import threading
import os

from p2pchatapp import P2PChatApp
from chatwindow import ChatWindow


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
            
            # Cria historico das conversas
            historicConversation = self.folder_path + "/" + str(host) +"_"+ str(port) + ".txt"
            
            if not os.path.exists(historicConversation):
                open(historicConversation, "x")
                print(f"File '{historicConversation}' created.")
                
            #Cria lista de contatos
            contactsListPath = self.folder_path + "/" + self.contactsListFile
            
            if not os.path.exists(contactsListPath):
                open(contactsListPath, "a").write(str(host) +"_"+ str(port) + "-" + name + "\n")
                
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
        """Send plaintext data."""
        try:
            self.message = message
            connection_info = self.connections[name]

            # Retrieve host and port of the recipient
            self.hostToMsg, self.portToMsg = connection_info.get('address')
            
            print("MESSAGE 1::::" + message)
            # Prefix the message with its length
            message = message.encode()
            #message_length = len(message).to_bytes(4, 'big')  # Use 4 bytes for length
            connection_info['socket'].sendall(message)
            
            host_port=str(self.host) +"_"+ str(self.port)
            print("MESSAGE 2::::" + host_port)
            connection_info['socket'].sendall(host_port.encode()) #Envia host e port
            
            
            print(f"Message to {name} delivered successfully.")

            open(self.folder_path + "/" + str(self.hostToMsg) +"_"+ str(self.portToMsg) + ".txt", "a").write("You- " + self.message + "\n")

        except socket.error as e:
            print(f"Failed to send data. Error: {e}")



    def handle_client(self, connection, name):
        """Handle incoming messages from a client."""
        while True:
            try:
                
                # Then, read the exact number of bytes for the actual message
                #data = connection.recv(1024)

                #if not data:
                    #break
                
                # Decode the received data
                #message = data.decode()
                
                host_port=connection.recv(1024).decode() #Recebe host e port
                print("HOST_PORT:::" + host_port + "\n")
                host, port = host_port.split("_")                
                    
                print(f"\nReceived data from {host + ":" + port}: {message}")

                open(self.folder_path + "/" + str(host) +"_"+ str(port) + ".txt", "a").write(host + ":" + port + "- " + message + "\n")
                contactsListPath = self.folder_path + "/" + self.contactsListFile
                if not os.path.exists(contactsListPath):
                    open(contactsListPath, "x")
                    
                c = None
                with open(contactsListPath, 'r') as file:
                    contacts = file.readlines()
                    
                    if not contacts:
                        open(contactsListPath, "a").write(str(host) +"_"+ str(port) + "-" + str(host) +":"+ str(port) + "\n")
                        
                    # Adicionar os contactos à listbox
                    for contact in contacts:
                        contact_ip = contact.strip().split('-')[0]  # Remover quebras de linha
                        h_p = host+"_"+port
                        if contact_ip == h_p:
                            break
                        else:
                            open(contactsListPath, "a").write(str(host) +"_"+ str(port) + "-" + str(host) +":"+ str(port) + "\n")

                # Notify all clients except the sender
                #self.notify_all_clients(f"{host}:{port}- {message}", sender_socket=connection)
                
                self.connections[host+":"+port] = {
                    'socket': connection,
                    'address': (host, port)  # Store address properly
                }
                if name in self.connections:
                    del self.connections[name]
                print(self.connections)
                print(f"Still connected to {host}:{port} at {host}:{port}")
                    
##################### Cliente que enviou mesagem recebe a confirmação e regista no historico da conversa ###################################################################
                #if message.startswith("ACK"):
                #    print(self.message)
                #    print(f"Message to {name} delivered successfully.")
                #    open(self.folder_path + "/" + str(self.hostToMsg) +"_"+ str(self.portToMsg) + ".txt", "a").write("You- " + self.message + "\n")

            except socket.error as e:
                print(f"Socket error: {e}")
                break

        print(f"Connection from {name} closed.")
        del self.connections[name]
        connection.close()


        print(f"Connection from {name} closed.")
        del self.connections[name]
        connection.close()


    def notify_all_clients(self, message, sender_socket):
        for client_name, client_info in self.connections.items():
            #print(client_info)
            if client_info['socket'] != sender_socket:
                # Send the message from the client with their name
                #print("NOTIFY"+message)
                client_info['socket'].sendall(message.encode())


    def start(self):
        """Start listening for connections."""
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

    def get_connected_clients(self):
        """Return a list of connected clients."""
        return [(name, info['address'][0], info['address'][1]) for name, info in self.connections.items() if 'address' in info]

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Start a peer in the P2P network.")
    parser.add_argument("--host", type=str, required=True, help="Host IP for this peer")
    parser.add_argument("--port", type=int, required=True, help="Port number for this peer")

    args = parser.parse_args()

    peer = Peer(args.host, args.port)
    peer.start()

    app = P2PChatApp(peer)

    try:
        app.mainloop()
    except KeyboardInterrupt:
        print("\nShutting down the program...")
        sys.exit(0)
