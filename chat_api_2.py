import socket
import threading
import os
import uuid
import tkinter as tk
from tkinter import messagebox, scrolledtext


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
            
            self.hostToMsg, self.portToMsg = connection_info.get('address')
            
            connection_info['socket'].sendall(("MSG:"+message).encode()) #Envia mensage
            
            host_port=str(self.host) +"_"+ str(self.port)
            connection_info['socket'].sendall(("MSG:"+host_port).encode()) #Envia host e port

        except socket.error as e:
            print(f"Failed to send data. Error: {e}")

    def handle_client(self, connection, name):
        """Handle incoming messages from a client."""
        while True:
            try:
                
                data = connection.recv(1024) #Recebe mensagem
                
                if not data:
                    break
                message = data.decode()
                
                if message.startswith("MSG:"):
                    host_port=connection.recv(1024).decode() #Recebe host e port
                    host_port = host_port[4:] #Remove o prefixo "MSG:"
                    host, port = host_port.split("_")
                    
                    message = message[4:]  #Remove o prefixo "MSG:"
                    print(f"\nReceived data from {host + ":" + port}: {message}")


                    open(self.folder_path + "/" + str(host) +"_"+ str(port) + ".txt", "a").write(host + ":" + port + "-" + message + "\n")
                    contactsListPath = self.folder_path + "/" + self.contactsListFile
                    if not os.path.exists(contactsListPath):
                        open(contactsListPath, "a").write(str(host) +"_"+ str(port) + "-" + str(host) +":"+ str(port) + "\n")

                    # Envia confirmação de recebimento
                    connection.sendall("ACK".encode()) #Envia confirmação

                    # Notify all clients except the sender
                    self.notify_all_clients(f"{name}: {message}", sender_socket=connection)
                    
                    self.connections[name] = {
                        'socket': connection,
                        'address': (host, port)  # Store address properly
                    }
                    print(self.connections)
                    print(f"Connected to {name} at {host}:{port}")
                    
##################### Cliente que enviou mesagem recebe a confirmação e regista no historico da conversa ###################################################################
                if message.startswith("ACK"):
                    print(self.message)
                    print(f"Message to {name} delivered successfully.")
                    open(self.folder_path + "/" + str(self.hostToMsg) +"_"+ str(self.portToMsg) + ".txt", "a").write("You-" + self.message + "\n")

            except socket.error as e:
                print(f"Socket error: {e}")
                break

        print(f"Connection from {name} closed.")
        del self.connections[name]
        connection.close()

    def notify_all_clients(self, message, sender_socket=None):
        """Notify all clients about a new message, except the sender."""
        for name, conn_info in self.connections.items():
            if conn_info['socket'] != sender_socket:  # Exclude the sender
                try:
                    conn_info['socket'].sendall(message.encode())
                except socket.error as e:
                    print(f"Failed to notify client {name}. Error: {e}")
                    continue

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

    def clear_frame(self):
        """Clear the current frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def open_new_connection_frame(self):
        """Open the frame for new connections."""
        self.clear_frame()

        tk.Label(self.main_frame, text="New Connection", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.main_frame, text="Host:").pack()
        self.entry_host = tk.Entry(self.main_frame)
        self.entry_host.pack(fill=tk.X, padx=10)

        tk.Label(self.main_frame, text="Port:").pack()
        self.entry_port = tk.Entry(self.main_frame)
        self.entry_port.pack(fill=tk.X, padx=10)

        tk.Label(self.main_frame, text="Client Name:").pack()
        self.entry_name = tk.Entry(self.main_frame)
        self.entry_name.pack(fill=tk.X, padx=10)

        self.connect_button = tk.Button(self.main_frame, text="Connect", command=self.connect)
        self.connect_button.pack(pady=20)

        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack()

    def connect(self):
        host = self.entry_host.get()
        port = int(self.entry_port.get())
        client_name = self.entry_name.get()

        self.peer.connect(host, port, client_name)
        messagebox.showinfo("Connection", f"Connected to {client_name}!")

    def open_view_clients_frame(self):
        """Open the frame to view connected clients."""
        self.clear_frame()
        tk.Label(self.main_frame, text="Connected Clients", font=("Arial", 16)).pack(pady=10)

        self.client_listbox = tk.Listbox(self.main_frame)
        self.client_listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        self.load_clients()

        self.start_chat_button = tk.Button(self.main_frame, text="Start Chat", command=self.start_chat)
        self.start_chat_button.pack(pady=10)
        
        self.edit_name_button = tk.Button(self.main_frame, text="Edit Contact Name", command=self.edit_client_name)
        self.edit_name_button.pack(pady=10)

        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack()

    def edit_client_name(self):
        """Edit the name of the selected client."""
        selected_client = self.client_listbox.curselection()
        if selected_client:
            client_name = self.client_listbox.get(selected_client)

            # Abrir uma nova janela para edição
            edit_window = tk.Toplevel(self)
            edit_window.title(f"Edit Name of {client_name}")
            edit_window.geometry("300x150")

            tk.Label(edit_window, text="Enter new name:").pack(pady=10)
            new_name_entry = tk.Entry(edit_window)
            new_name_entry.pack(pady=5, padx=20)

            def save_new_name():
                new_name = new_name_entry.get()
                if new_name:
                    # Obtenha o IP e Porta do cliente selecionado
                    client_info = self.peer.connections[client_name]
                    host, port = client_info['address']

                    # Caminho para o ficheiro contacts.txt
                    contacts_list_path = os.path.join(self.peer.folder_path, self.peer.contactsListFile)
                    contactsListPath = self.peer.folder_path + "/" + self.peer.contactsListFile
                    if os.path.exists(contactsListPath):
                        with open(contactsListPath, "r") as file:
                            lines = file.readlines()

                        # Procurar e modificar a linha correspondente ao contato
                        updated_lines = []
                        for line in lines:
                            print(line)
                            contact_ip_port, contact_name = line.strip().split('-')
                            print(contact_ip_port)
                            print(contact_name)
                            if contact_ip_port == f"{host}_{port}":
                                # Substituir pelo novo nome
                                updated_lines.append(f"{contact_ip_port}-{new_name}\n")
                            else:
                                updated_lines.append(line)

                        # Reescrever o ficheiro com o nome atualizado
                        with open(contactsListPath, 'w') as file:
                            file.writelines(updated_lines)

                        print(self.peer.connections)
                        # Atualizar o nome na lista de conexões (dicionário interno)
                        connection_data  = self.peer.connections.pop(client_name)
                        self.peer.connections[new_name] = connection_data
                        print(self.peer.connections)
                        # Atualizar a listbox de clientes
                        self.load_clients()

                        messagebox.showinfo("Success", f"Contact name updated to {new_name}")
                        edit_window.destroy()
                    else:
                        messagebox.showerror("Error", "Contacts file not found.")
                else:
                    messagebox.showwarning("Invalid Input", "Please enter a valid name.")

            tk.Button(edit_window, text="Save", command=save_new_name).pack(pady=10)

        else:
            messagebox.showwarning("Invalid Selection", "Please select a client to edit the name.")


    def load_clients(self):
        """Load the list of connected clients."""
        self.client_listbox.delete(0, tk.END)
        for (name, host, port) in self.peer.get_connected_clients():
            self.client_listbox.insert(tk.END, name)

    def start_chat(self):
        selected_client = self.client_listbox.curselection()
        if selected_client:
            client_name = self.client_listbox.get(selected_client)
            self.chat_window = ChatWindow(self.peer, client_name)
        else:
            messagebox.showwarning("Invalid Selection", "Please select a client to start the chat.")

    def on_close(self):
        """Close the application and shut down the server."""
        self.peer.socket.close()
        self.destroy()


class ChatWindow(tk.Toplevel):
    def __init__(self, peer, client_name):
        super().__init__()
        self.peer = peer
        self.client_name = client_name
        self.title(f"Chat with {client_name}")
        self.geometry("400x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.chat_display = scrolledtext.ScrolledText(self, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        self.entry_message = tk.Entry(self)
        self.entry_message.pack(fill=tk.X, padx=10, pady=10)
        self.entry_message.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Start listening for messages in a separate thread
        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

    def send_message(self, event=None):
        """Send a message to the selected peer."""
        self.message = self.entry_message.get()
        if self.message:
            self.peer.send_data(self.client_name, self.message)
            self.display_message(f"You: {self.message}")
            self.entry_message.delete(0, tk.END)

    def display_message(self, message):
        """Display the message in the chat window."""
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{message}\n")
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)

    def listen_for_messages(self):
        """Listen for incoming messages from the selected peer."""
        while True:
            try:
                for name, connection_info in self.peer.connections.items():
                    if name != self.client_name:
                        data = connection_info['socket'].recv(1024)
                        if data:
                            message = data.decode()
                            self.display_message(f"{name}: {message}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def on_close(self):
        self.destroy()


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
