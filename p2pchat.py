import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os

class Peer:
    def __init__(self, ip, port, connection):
        self.ip = ip
        self.port = port
        self.connection = connection
        self.chat_window = None

class P2PChatApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = {}
        self.server_socket = None

        # Inicia a interface gráfica
        self.root = tk.Tk()
        self.root.title(f"Client/Server: {host}:{port}")
        self.root.geometry("500x500")  # Ajusta o tamanho da janela
        self.root.minsize(500, 500)  # Define um tamanho mínimo

        self.current_frame = None
        self.setup_main_menu()

        # Inicia o servidor em uma nova thread
        threading.Thread(target=self.start_server, daemon=True).start()

    def setup_main_menu(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        self.connect_button = tk.Button(self.current_frame, text="Connect to new peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        self.list_button = tk.Button(self.current_frame, text="List of connected peers", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    def show_connection_inputs(self):
        self.clear_frame()

        tk.Label(self.current_frame, text="Enter the peer IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.current_frame, text="Enter the peer port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        self.connect_peer_button = tk.Button(self.current_frame, text="Connect", command=self.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def clear_frame(self):
        for widget in self.current_frame.winfo_children():
            widget.destroy()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

        while True:
            conn, addr = self.server_socket.accept()
            peer_ip, peer_port = addr

            if peer_ip not in self.peers:
                peer = Peer(peer_ip, peer_port, conn)
                self.peers[peer_ip] = peer
                print(f"New peer connected: {peer_ip}:{peer_port}")
                threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            else:
                print(f"Existing peer connected again: {peer_ip}:{peer_port}")
                self.peers[peer_ip].connection = conn
                threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()

    def connect_to_peer(self):
        peer_ip = self.peer_ip_entry.get()
        peer_port = self.peer_port_entry.get()

        if peer_ip and peer_port:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_ip, int(peer_port)))

                if peer_ip not in self.peers:
                    peer = Peer(peer_ip, int(peer_port), sock)
                    self.peers[peer_ip] = peer
                    threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
                    messagebox.showinfo("Connection successful", f"Connected to {peer_ip}:{peer_port}")
                else:
                    self.peers[peer_ip].connection = sock
                    threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()
                    messagebox.showinfo("Connection successful", f"Reusing connection to {peer_ip}:{peer_port}")

                self.setup_main_menu()

            except Exception as e:
                messagebox.showerror("Connection error", f"Could not connect to {peer_ip}:{peer_port}\nErro: {e}")

    def receive_messages(self, peer):
        while True:
            try:
                message = peer.connection.recv(1024).decode("utf-8")
                if message:
                    print(f"Message received from {peer.ip}:{peer.port}: {message}")
                    if peer.chat_window:
                        self.update_chat_window(peer, message, sender=False)
                    self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")
            except:
                print(f"Connection to {peer.ip}:{peer.port} closed.")
                peer.connection.close()
                break

    def show_peer_list(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Peers Connected.")
        label.pack(pady=10)

        if not self.peers:
            label = tk.Label(self.current_frame, text="No peer connected.")
            label.pack(pady=10)
        else:
            listbox = tk.Listbox(self.current_frame)
            for idx, peer_ip in enumerate(self.peers):
                listbox.insert(idx, f"{peer_ip}:{self.peers[peer_ip].port}")
            listbox.pack(pady=10)

            def open_chat():
                selected_idx = listbox.curselection()
                if selected_idx:
                    selected_peer_ip = listbox.get(selected_idx[0]).split(':')[0]
                    selected_peer = self.peers[selected_peer_ip]
                    self.open_chat_window(selected_peer)

            open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, peer):
        if self.current_frame:
            self.current_frame.destroy()

        peer.chat_window = None

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        chat_label = tk.Label(self.current_frame, text=f"Chat to {peer.ip}:{peer.port}")
        chat_label.pack(pady=10)

        # Área de texto do chat ajustada
        text_area = tk.Text(self.current_frame, height=15, width=50)  # Tamanho ajustado para garantir visibilidade
        text_area.pack(pady=10)
        text_area.config(state=tk.DISABLED)

        # Carregar histórico de conversa do arquivo
        self.load_chat_from_file(peer, text_area)

        message_var = tk.StringVar()
        message_entry = tk.Entry(self.current_frame, textvariable=message_var)
        message_entry.pack(fill=tk.X, padx=10, pady=5)

        # Frame para centralizar os botões
        button_frame = tk.Frame(self.current_frame)
        button_frame.pack(pady=10)

        send_button = tk.Button(button_frame, text="Send", command=lambda: self.send_message(peer, message_var, text_area))
        send_button.pack(side=tk.LEFT, padx=10)

        back_button = tk.Button(button_frame, text="Back", command=self.show_peer_list)
        back_button.pack(side=tk.LEFT, padx=10)

        # Bind Enter key to send message
        message_entry.bind('<Return>', lambda event: self.send_message(peer, message_var, text_area))

        peer.chat_window = {
            'text_area': text_area
        }

    def send_message(self, peer, message_var, text_area):
        message = message_var.get()
        if message:
            message_var.set("")  # Limpa o campo de entrada
            peer.connection.sendall(message.encode("utf-8"))
            self.update_chat_window(peer, message, sender=True)
            self.save_chat_to_file(peer, f"You: {message}")

    def update_chat_window(self, peer, message, sender=False):
        if peer.chat_window:
            text_area = peer.chat_window['text_area']
            text_area.config(state=tk.NORMAL)
            if sender:
                text_area.insert(tk.END, f"You: {message}\n")
            else:
                text_area.insert(tk.END, f"{peer.ip}:{peer.port}: {message}\n")
            text_area.config(state=tk.DISABLED)
            text_area.see(tk.END)

    def save_chat_to_file(self, peer, message):
        # Salva a conversa em um arquivo
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        with open(filename, 'a') as f:
            f.write(message + '\n')

    def load_chat_from_file(self, peer, text_area):
        # Carrega o histórico de conversa de um arquivo
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                chat_history = f.read()
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, chat_history)
                text_area.config(state=tk.DISABLED)

# Função principal para iniciar o cliente-servidor
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal para perguntar porta do servidor

    # Pergunta a porta local do cliente
    local_port = simpledialog.askinteger("Port", "Enter local port:")
    root.destroy()

    # Inicia a aplicação P2P
    if local_port:
        host = socket.gethostbyname(socket.gethostname())  # Obtém o IP local
        app = P2PChatApp(host, local_port)
        app.root.mainloop()

if __name__ == "__main__":
    start_peer()
