import socket
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class Peer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connections = {}  # Armazenar conexões ativas
        self.keys = self.generate_keys()  # Chaves do cliente

    def generate_keys(self):
        """Gera um par de chaves RSA."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return (private_key, public_key)

    def serialize_public_key(self, public_key):
        """Serializa a chave pública para envio."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def encrypt_message(self, public_key, message):
        """Criptografa uma mensagem usando a chave pública."""
        return public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def decrypt_message(self, encrypted_message):
        """Descriptografa uma mensagem usando a chave privada."""
        try:
            return self.keys[0].decrypt(
                encrypted_message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def connect(self, host, port, name):
        try:
            connection = socket.create_connection((host, port))
            public_key = self.serialize_public_key(self.keys[1])
            self.connections[name] = {
                'socket': connection,
                'public_key': public_key,
                'address': (host, port)  # Armazenando o endereço corretamente
            }
            print(f"Connected to {name} at {host}:{port}")
            threading.Thread(target=self.handle_client, args=(connection, name)).start()
            self.send_public_key(name)  # Enviar a chave pública após a conexão
        except socket.error as e:
            print(f"Failed to connect to {host}:{port}. Error: {e}")

    def listen(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(10)
        print(f"Listening for connections on {self.host}:{self.port}")

        while True:
            try:
                (connection, address) = self.socket.accept()
                name = f"{address[0]}:{address[1]}"
                self.connections[name] = {'socket': connection}
                threading.Thread(target=self.handle_client, args=(connection, name)).start()
            except OSError as e:
                print(f"Socket error: {e}")
                break

    def send_data(self, name, message):
        """Envia dados criptografados."""
        try:
            connection_info = self.connections[name]
            public_key = serialization.load_pem_public_key(connection_info['public_key'])
            encrypted_message = self.encrypt_message(public_key, message)  # Enviar mensagem criptografada
            connection_info['socket'].sendall(encrypted_message)
        except socket.error as e:
            print(f"Failed to send data. Error: {e}")

    def handle_client(self, connection, name):
        # Recebe a chave pública do cliente que se conecta
        while True:
            try:
                data = connection.recv(1024)
                if not data:
                    break
                if name not in self.connections:
                    self.connections[name]['public_key'] = data  # Armazenar chave pública do cliente
                    print(f"Received public key from {name}")
                else:
                    message = self.decrypt_message(data)
                    if message is not None:
                        print(f"\nReceived data from {name}: {message}")
                        self.notify_all_clients(f"{name}: {message}")  # Notifica todos os clientes
            except socket.error as e:
                print(f"Socket error: {e}")
                break

        print(f"Connection from {name} closed.")
        del self.connections[name]
        connection.close()

    def notify_all_clients(self, message):
        """Notifica todos os clientes sobre uma nova mensagem recebida."""
        for name, conn_info in self.connections.items():
            try:
                conn_info['socket'].sendall(message.encode())
            except socket.error as e:
                print(f"Failed to notify client {name}. Error: {e}")
                continue

    def send_public_key(self, name):
        """Envia a chave pública do cliente para a conexão."""
        connection_info = self.connections[name]
        connection_info['socket'].sendall(self.serialize_public_key(self.keys[1]))

    def start(self):
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

    def get_connected_clients(self):
        """Retorna a lista de clientes conectados."""
        return [(name, info['address'][0], info['address'][1]) for name, info in self.connections.items() if 'address' in info]

    def get_connection(self, name):
        """Retorna a conexão para um cliente específico."""
        return self.connections.get(name, None)


class P2PChatApp(tk.Tk):
    def __init__(self, peer):
        super().__init__()
        self.peer = peer
        self.title("P2P Chat App")
        self.geometry("400x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # Frame principal
        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Exibir o próprio IP
        self.ip_label = tk.Label(self.main_frame, text=f"Seu IP: {self.peer.host}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        # Menu inicial
        self.create_menu()

    def create_menu(self):
        """Cria o menu inicial com opções."""
        self.clear_frame()

        self.label = tk.Label(self.main_frame, text="Bem-vindo ao P2P Chat", font=("Arial", 16))
        self.label.pack(pady=20)

        self.create_connection_button = tk.Button(self.main_frame, text="Criar Nova Conexão", command=self.open_new_connection_frame)
        self.create_connection_button.pack(pady=10)

        self.view_clients_button = tk.Button(self.main_frame, text="Ver Clientes Conectados", command=self.open_view_clients_frame)
        self.view_clients_button.pack(pady=10)

    def clear_frame(self):
        """Limpa o frame atual."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def open_new_connection_frame(self):
            """Abre o frame de nova conexão."""
            self.clear_frame()

            tk.Label(self.main_frame, text="Nova Conexão", font=("Arial", 16)).pack(pady=10)

            tk.Label(self.main_frame, text="Host:").pack()
            self.entry_host = tk.Entry(self.main_frame)
            self.entry_host.pack(fill=tk.X, padx=10)

            tk.Label(self.main_frame, text="Port:").pack()
            self.entry_port = tk.Entry(self.main_frame)
            self.entry_port.pack(fill=tk.X, padx=10)

            tk.Label(self.main_frame, text="Nome do Cliente:").pack()
            self.entry_name = tk.Entry(self.main_frame)
            self.entry_name.pack(fill=tk.X, padx=10)

            self.connect_button = tk.Button(self.main_frame, text="Conectar", command=self.connect)
            self.connect_button.pack(pady=20)

            self.back_button = tk.Button(self.main_frame, text="Voltar", command=self.create_menu)
            self.back_button.pack()

    def connect(self):
        host = self.entry_host.get()
        port = int(self.entry_port.get())
        client_name = self.entry_name.get()

        self.peer.connect(host, port, client_name)
        messagebox.showinfo("Conexão", f"Conectado a {client_name}!")

    def open_view_clients_frame(self):
        """Abre o frame para ver clientes conectados."""
        self.clear_frame()
        tk.Label(self.main_frame, text="Clientes Conectados", font=("Arial", 16)).pack(pady=10)

        self.client_listbox = tk.Listbox(self.main_frame)
        self.client_listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        self.load_clients()

        self.start_chat_button = tk.Button(self.main_frame, text="Iniciar Chat", command=self.start_chat)
        self.start_chat_button.pack(pady=10)

        self.back_button = tk.Button(self.main_frame, text="Voltar", command=self.create_menu)
        self.back_button.pack()

    def load_clients(self):
        """Carrega a lista de clientes conectados."""
        self.client_listbox.delete(0, tk.END)  # Limpa a lista atual
        for (name, host, port) in self.peer.get_connected_clients():
            self.client_listbox.insert(tk.END, name)  # Exibir o nome do cliente

    def start_chat(self):
        selected_client = self.client_listbox.curselection()
        if selected_client:
            client_name = self.client_listbox.get(selected_client)
            self.chat_window = ChatWindow(self.peer, client_name)
        else:
            messagebox.showwarning("Seleção Inválida", "Por favor, selecione um cliente para iniciar o chat.")

    def on_close(self):
        """Fecha a aplicação e encerra o servidor."""
        self.peer.socket.close()
        self.destroy()


class ChatWindow(tk.Toplevel):
    def __init__(self, peer, client_name):
        super().__init__()
        self.peer = peer
        self.client_name = client_name
        self.title(f"Chat com {client_name}")
        self.geometry("400x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.chat_display = scrolledtext.ScrolledText(self, state=tk.DISABLED)
        self.chat_display.pack(fill=tk.BOTH, expand=True)

        self.entry_message = tk.Entry(self)
        self.entry_message.pack(fill=tk.X, padx=10, pady=10)
        self.entry_message.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self, text="Enviar", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT)

        # Iniciar o recebimento de mensagens em uma thread
        self.listen_thread = threading.Thread(target=self.listen_for_messages, daemon=True)
        self.listen_thread.start()

    def send_message(self, event=None):
        message = self.entry_message.get()
        if message:
            self.peer.send_data(self.client_name, message)
            self.display_message(f"Você: {message}")
            self.entry_message.delete(0, tk.END)

    def display_message(self, message):
        self.chat_display.configure(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{message}\n")
        self.chat_display.configure(state=tk.DISABLED)
        self.chat_display.see(tk.END)  # Rolagem automática para a última mensagem

    def listen_for_messages(self):
        """Função para ouvir mensagens do cliente selecionado."""
        while True:
            try:
                # Aqui, você deve percorrer todas as conexões para verificar se há mensagens
                for name, connection_info in self.peer.connections.items():
                    if name != self.client_name:  # Ignora mensagens enviadas para si mesmo
                        data = connection_info['socket'].recv(1024)
                        if data:
                            message = self.peer.decrypt_message(data)
                            if message is not None:
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
        print("\nEncerrando o programa...")
        sys.exit(0)
