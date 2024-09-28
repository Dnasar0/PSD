import socket
import threading
import argparse
import time

class Peer:
    
    def __init__(self, host, port) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = []
        self.peers = {}
        self.stop_event = threading.Event() 
        self.lock = threading.Lock()
        
    def connect(self, host, port):
        try:
            connection = socket.create_connection((host, port))
            with self.lock:
                self.connections.append(connection)
                self.peers[(host, port)] = connection
            print(f"Connected to {host}:{port}")
            threading.Thread(target=self.handle_client, args=(connection, (host, port)), daemon=True).start()
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}\n")        
            
    def listen(self):
        try:
            self.socket.bind((self.host, self.port))
            print(f"Successfully bound to {self.host}:{self.port}")
        except socket.error as e:
            print(f"Failed to bind socket: {e}")
            return
        
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}\n")

        while not self.stop_event.is_set():
            print("Waiting for a connection...")
            try:
                self.socket.settimeout(30)  # Increased timeout to 10 seconds
                (connection, address) = self.socket.accept()
                print("Connection accepted!")
                with self.lock:
                    self.connections.append(connection)
                    self.peers[address] = connection
                print(f"\nAccepted connection from {address}")
                threading.Thread(target=self.handle_client, args=(connection, address)).start()
            except socket.timeout:
                continue  # Just continue without printing anything
            except socket.error as e:
                if self.stop_event.is_set():
                    break
                print(f"Socket error: {e}")
            
    def send_data(self, data, peer_address=None):
        if peer_address:
            connection = self.peers.get(peer_address)
            if connection:
                try:
                    connection.sendall(data.encode())
                except socket.error as e:
                    print(f"Failed to send data to {peer_address}. Error: {e}\n")
                    with self.lock:
                        self.connections.remove(connection)
                        del self.peers[peer_address]
        else:
            with self.lock:
                for connection in self.connections:
                    try:
                        connection.sendall(data.encode())
                    except socket.error as e:
                        print(f"Failed to send data. Error: {e}\n")
                        self.connections.remove(connection)

    def handle_client(self, connection, address):
        while not self.stop_event.is_set():
            try:
                data = connection.recv(1024)
                if not data:
                    break
                print(f"\nReceived data from {address}: {data.decode()}\n")
            except socket.error:
                break
            
        print(f"\nConnection from {address} closed.\n")
        with self.lock:
            self.connections.remove(connection)
            del self.peers[address]
        connection.close()

    def list_peers(self):
        with self.lock:
            return list(self.peers.keys())
        
    def start(self):
        listen_thread = threading.Thread(target=self.listen, daemon=True)
        listen_thread.start()
        
    def stop(self):
        self.stop_event.set()
        for connection in self.connections:
            connection.close()
        self.socket.close()        
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Start a peer in the P2P network.")
    parser.add_argument("--host", type=str, required=True, help="Host IP for this peer")
    parser.add_argument("--port", type=int, required=True, help="Port number for this peer")
    parser.add_argument("--connect-host", type=str, help="Host IP of the peer to connect to")
    parser.add_argument("--connect-port", type=int, help="Port number of the peer to connect to")

    args = parser.parse_args()

    node = Peer(args.host, args.port)
    node.start()
    time.sleep(1)
    
    if args.connect_host and args.connect_port:
        print(f"Attempting to connect to {args.connect_host}:{args.connect_port}...")
        node.connect(args.connect_host, args.connect_port)
        
    try:        
        while True:
            print("\nCommands: 'peers' to list active peers, 'send' to send a message, 'exit' to quit")
            command = input("Enter command: ").lower()
            
            if command == "exit":
                break
            elif command == "peers":
                peers = node.list_peers()
                if peers:
                    print("\nActive peers:")
                    for idx, peer in enumerate(peers):
                        print(f"{idx + 1}: {peer}")
                else:
                    print("No active peers found.")
            elif command == "send":
                peers = node.list_peers()
                if not peers:
                    print("No active peers to send messages to.")
                    continue
                
                for idx, peer in enumerate(peers):
                    print(f"{idx + 1}: {peer}")
                
                try:
                    choice = int(input("Select peer number: ")) - 1
                    selected_peer = peers[choice]
                except (ValueError, IndexError):
                    print("Invalid selection.")
                    continue
                
                message = input("Enter message to send: ")
                node.send_data(message, selected_peer)
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Shutting down...")

    node.stop()
    print("Peer has shut down.")
