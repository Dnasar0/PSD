import os
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext

class ChatWindow(tk.Toplevel):
    def __init__(self, peer, client_name, file_path):
        super().__init__()
        self.peer = peer
        self.client_name = client_name
        
        self.file_path = file_path  # Caminho do arquivo de histórico
        
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
        
        # Carregar o histórico do arquivo e exibi-lo na janela
        self.load_chat_history()

        # Start listening for messages in a separate thread
        self.listen_thread = threading.Thread(target=self.peer.listen, daemon=True)
        self.listen_thread.start()
        
    def load_chat_history(self):
        """Carregar histórico de mensagens do arquivo e exibir."""
        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as file:
                history = file.read()
            if history:
                self.chat_display.configure(state=tk.NORMAL)
                self.chat_display.insert(tk.END, history)
                self.chat_display.configure(state=tk.DISABLED)
                self.chat_display.see(tk.END)

    def send_message(self, event=None):
        """Send the message typed by the user."""
        message = self.entry_message.get()
        if message:

            self.display_message(f"You- {message}")

            self.peer.send_data(self.client_name, message)

            self.entry_message.delete(0, tk.END)

    def display_message(self, message):
        """Display the message in the chat window."""
        self.chat_display.configure(state=tk.NORMAL)
        print(message)
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
                            self.display_message(f"{name}- {message}")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def on_close(self):
        self.destroy()