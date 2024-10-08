import os
import tkinter as tk
from tkinter import messagebox

class P2PChatApp(tk.Tk):
    def __init__(self, peer):
        super().__init__()
        self.peer = peer
        self.title("P2P Chat App")
        self.geometry("600x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.current_chat_client = None  # Cliente com quem está conversando no momento

        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.create_menu()

    def create_menu(self):
        """Create the initial menu with options."""
        self.clear_frame()

        # Display IP and Port
        self.ip_label = tk.Label(self.main_frame, text=f"Your IP: {self.peer.host}\nYour Port: {self.peer.port}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        self.label = tk.Label(self.main_frame, text="Welcome to P2P Chat", font=("Arial", 16))
        self.label.pack(pady=20)

        # Button to create a new connection
        self.create_connection_button = tk.Button(self.main_frame, text="Create New Connection", command=self.open_new_connection_frame)
        self.create_connection_button.pack(pady=10)

        # Button to view connected clients and start chat
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
        """Handle connecting to a new peer."""
        host = self.entry_host.get()
        port = int(self.entry_port.get())
        client_name = self.entry_name.get()

        self.peer.connect(host, port, client_name)
        messagebox.showinfo("Connection", f"Connected to {client_name}!")

    def open_view_clients_frame(self):
        """Open the frame to view connected clients."""
        self.clear_frame()

        tk.Label(self.main_frame, text="Connected Clients", font=("Arial", 16)).pack(pady=10)

        clients = self.peer.get_connected_clients()

        if clients:
            for client in clients:
                client_name, host, port = client
                client_button = tk.Button(self.main_frame, text=f"{client_name} ({host}:{port})", command=lambda name=client_name: self.open_chat_window(name))
                client_button.pack(pady=5)
        else:
            tk.Label(self.main_frame, text="No clients connected.").pack(pady=10)

        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack()

    def open_chat_window(self, client_name):
        """Open a new window for chatting with the selected client."""
        chat_window = tk.Toplevel(self)
        chat_window.title(f"Chat with {client_name}")
        chat_window.geometry("400x400")

        # Create chat log text area
        chat_log = tk.Text(chat_window, state=tk.DISABLED)
        chat_log.pack(fill=tk.BOTH, expand=True)

        # Entry and send button for the chat
        entry_message = tk.Entry(chat_window)
        entry_message.pack(fill=tk.X, padx=10, pady=5)

        send_button = tk.Button(chat_window, text="Send", command=lambda: self.send_message(client_name, entry_message, chat_log))
        send_button.pack(pady=5)

        # Load the chat history
        self.load_chat_history(client_name, chat_log)
        
        # Save the chat window reference in the connection
        self.peer.connections[client_name]['chat_window'] = chat_log

    def load_chat_history(self, client_name, chat_log):
        """Load the chat history for the selected client."""
        chat_log.config(state=tk.NORMAL)
        chat_log.delete(1.0, tk.END)  # Clear the chat log

        # Load the conversation from the file
        host, port = self.peer.connections[client_name]['address']
        file_path = f"{self.peer.folder_path}/{host}_{port}.txt"

        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                history = f.read()
                chat_log.insert(tk.END, history)

        chat_log.config(state=tk.DISABLED)

    def send_message(self, client_name, entry_message, chat_log):
        """Send a message to the current chat client."""
        message = entry_message.get()
        if message and client_name:
            self.peer.send_data(client_name, message)
            self.display_message(chat_log, f"You: {message}")
            entry_message.delete(0, tk.END)

    def display_message(self, chat_log, message):
        """Display a message in the chat log."""
        chat_log.config(state=tk.NORMAL)
        chat_log.insert(tk.END, message + "\n")
        chat_log.config(state=tk.DISABLED)
        chat_log.see(tk.END)

    def on_close(self):
        """Handle app close event."""
        self.peer.socket.close()
        self.destroy()
