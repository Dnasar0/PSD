import os
import tkinter as tk
from tkinter import simpledialog
from p2pchat_phase1 import P2PChatApp

class Tk:
    def __init__(self, p2p, host, port):
        self.root = tk.Tk()
        self.root.title(f"Client/Server: {host}:{port}")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)
        self.host = host
        self.port = port
        self.p2p = p2p

        self.current_frame = None
        self.setup_main_menu()
        
    def get_root(self):
        return self.root
        
    def setup_main_menu(self):
        """
        Sets up the main menu of the GUI.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        self.connect_button = tk.Button(self.current_frame, text="Connect to a peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        self.list_button = tk.Button(self.current_frame, text="Peers List", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    def show_connection_inputs(self):
        """
        Displays the input fields to connect to a new peer.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Peer IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.current_frame, text="Peer Port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        self.connect_peer_button = tk.Button(self.current_frame, text="Connect", command=self.p2p.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def clear_frame(self):
        """
        Clears the current frame to load new widgets.
        """
        for widget in self.current_frame.winfo_children():
            widget.destroy()
            
    def show_peer_list(self):
            """
            Displays the list of connected peers.
            """
            if self.current_frame:
                self.current_frame.destroy()

            self.current_frame = tk.Frame(self.root)
            self.current_frame.pack(pady=20)

            label = tk.Label(self.current_frame, text="Connected Peers")
            label.pack(pady=10)

            if not self.p2p.peers:
                label = tk.Label(self.current_frame, text="No peer connected")
                label.pack(pady=10)
            else:
                listbox = tk.Listbox(self.current_frame)
                for idx, (peer_ip, peer_port) in enumerate(self.p2p.peers):
                    listbox.insert(idx, f"{peer_ip}:{peer_port}")
                listbox.pack(pady=10)

                def open_chat():
                    selected_idx = listbox.curselection()
                    if selected_idx:
                        selected_item = listbox.get(selected_idx[0])
                        selected_peer_ip, selected_peer_port = selected_item.split(':')
                        selected_peer_port = int(selected_peer_port)
                        selected_peer = self.p2p.peers[(selected_peer_ip, selected_peer_port)]
                        self.open_chat_window(selected_peer)

                open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
                open_chat_button.pack(pady=10)

            back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
            back_button.pack(pady=10)

    def open_chat_window(self, peer):
        """
        Opens a chat window for communication with the peer.
        """
        if peer.chat_window:
            peer.chat_window.lift()
            return

        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Chat with {peer.ip}:{peer.port}")
        chat_window.geometry("500x500")

        chat_text = tk.Text(chat_window, height=25, width=60, state=tk.DISABLED)
        chat_text.pack(pady=10)

        self.load_chat_from_file(peer, chat_text)

        message_var = tk.StringVar()
        message_entry = tk.Entry(chat_window, textvariable=message_var, width=50)
        message_entry.pack(pady=5, padx=10, fill=tk.X)

        send_button = tk.Button(chat_window, text="Send", command=lambda: self.p2p.send_message(peer, message_var, chat_text))
        send_button.pack(pady=5)

        message_entry.bind('<Return>', lambda event: self.p2p.send_message(peer, message_var, chat_text))

        peer.chat_window = chat_window

        def on_close():
            peer.chat_window = None
            chat_window.destroy()

        chat_window.protocol("WM_DELETE_WINDOW", on_close)
        
    def update_chat_window(self, peer, message, sender=False):
        """
        Updates the chat window with new messages.
        """
        if peer.chat_window:
            text_area = peer.chat_window.children.get('!text')
            if text_area:
                text_area.config(state=tk.NORMAL)
                if sender:
                    text_area.insert(tk.END, f"You: {message}\n")
                else:
                    text_area.insert(tk.END, f"{peer.ip}:{peer.port}: {message}\n")
                text_area.config(state=tk.DISABLED)
                text_area.see(tk.END)
                
    def load_chat_from_file(self, peer, text_area):
        """
        Loads the conversation history from a file.
        """
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                chat_history = f.read()
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, chat_history)
                text_area.config(state=tk.DISABLED)