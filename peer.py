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
        self.stop_event = threading.Event() # ChatGPT 
        
    def connect(self, host, port):
        try:
            connection = socket.create_connection((host,port))
            self.connections.append(connection)
            print(f"Connected to {host}:{port}")
            threading.Thread(target=self.handle_client, args=(connection, (host,port)), daemon=True).start()
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}\n")        
            
    def listen(self):
        self.socket.bind((self.host,self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}\n")
        
        while not self.stop_event.is_set():
            try:
                (connection, address) = self.socket.accept()
                self.connections.append(connection)
                print(f"\nAccepted connection from {address}")
                threading.Thread(target=self.handle_client, args=(connection, address)).start()
            except socket.timeout:
                continue
            except socket.error as e:
                if self.stop_event.is_set():
                    break
                print(f"Socket error: {e}")
            
    def send_data(self,data):
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
        self.connections.remove(connection)
        connection.close()
        
    def start(self):
        listen_thread = threading.Thread(target=self.listen, daemon=True)
        listen_thread.start()
        
    # ChatGPT
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
        node.connect(args.connect_host, args.connect_port)

    try:        
        while True:
            message = input("Enter message to send (or 'exit' to quit): ")
            if message.lower() == "exit":
                break
            node.send_data(message)        
    except KeyboardInterrupt:
        print("Keyboard interrupt detected. Shutting down...")

    node.stop()
    print("Peer has shut down.")    