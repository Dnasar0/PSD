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
        
    def connect(self, host, port):
        try:
            connection = socket.create_connection((host,port))
            self.connections.append(connection)
            print(f"Connected to {host}:{port}")
            threading.Thread(target=self.handle_client, args=(connection, (host,port))).start()
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}")        
            
    def listen(self):
        self.socket.bind((self.host,self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")
        
        while True:
            (connection, address) = self.socket.accept()
            self.connections.append(connection)
            print(f"Accepted connection from {address}")
            threading.Thread(target=self.handle_client, args=(connection, address)).start()
            
    def send_data(self,data):
        for connection in self.connections:
            try:
                connection.sendall(data.encode())
            except socket.error as e:
                print(f"Failed to send data. Error: {e}")
                self.connections.remove(connection)
                
    def handle_client(self, connection, address):
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                print(f"\nReceived data from {address}: {data.decode()}")
            except socket.error:
                break
            
        print(f"Connection from {address} closed.")
        self.connections.remove(connection)
        connection.close()
        
    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()
        
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
        node.connect(args.connect_host, args.connect_port)

    while True:
        message = input("\nEnter message to send (or 'exit' to quit): ")
        if message.lower() == "exit":
            break
        node.send_data(message)        
        