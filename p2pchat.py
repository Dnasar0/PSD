import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

class Peer:
    def __init__(self, ip, port, connection, public_key):
        self.ip = ip
        self.port = port
        self.connection = connection
        self.public_key = public_key  # Chave pública do peer
        self.chat_window = None

class P2PChatApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = {}
        self.server_socket = None

        # Gera o par de chaves RSA para o aplicativo
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

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

        self.info_label = tk.Label(self.current_frame, text=f"Seu IP: {self.host}\nSua Porta: {self.port}")
        self.info_label.pack(pady=10)

        self.connect_button = tk.Button(self.current_frame, text="Conectar a um novo peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        self.list_button = tk.Button(self.current_frame, text="Lista de peers conectados", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    def show_connection_inputs(self):
        self.clear_frame()

        tk.Label(self.current_frame, text="Digite o IP do peer:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.current_frame, text="Digite a porta do peer:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        self.connect_peer_button = tk.Button(self.current_frame, text="Conectar", command=self.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def clear_frame(self):
        for widget in self.current_frame.winfo_children():
            widget.destroy()

    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Servidor escutando em {self.host}:{self.port}")

        while True:
            conn, addr = self.server_socket.accept()
            peer_ip, peer_port = addr

            try:
                # Recebe a chave pública do peer
                peer_public_key_bytes = self.receive_all(conn)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

                # Envia a chave pública do servidor para o peer
                conn.sendall(self.public_key_bytes)

                if peer_ip not in self.peers:
                    peer = Peer(peer_ip, peer_port, conn, peer_public_key)
                    self.peers[peer_ip] = peer
                    print(f"Novo peer conectado: {peer_ip}:{peer_port}")
                    threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
                else:
                    print(f"Peer existente reconectado: {peer_ip}:{peer_port}")
                    self.peers[peer_ip].connection = conn
                    self.peers[peer_ip].public_key = peer_public_key
                    threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()

            except Exception as e:
                print(f"Erro ao estabelecer conexão com {peer_ip}:{peer_port}: {e}")
                conn.close()

    def connect_to_peer(self):
        peer_ip = self.peer_ip_entry.get()
        peer_port = self.peer_port_entry.get()

        if peer_ip and peer_port:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((peer_ip, int(peer_port)))

                # Envia a chave pública do cliente para o peer
                sock.sendall(self.public_key_bytes)

                # Recebe a chave pública do peer
                peer_public_key_bytes = self.receive_all(sock)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

                if peer_ip not in self.peers:
                    peer = Peer(peer_ip, int(peer_port), sock, peer_public_key)
                    self.peers[peer_ip] = peer
                    threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
                    messagebox.showinfo("Conexão bem-sucedida", f"Conectado a {peer_ip}:{peer_port}")
                else:
                    self.peers[peer_ip].connection = sock
                    self.peers[peer_ip].public_key = peer_public_key
                    threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()
                    messagebox.showinfo("Conexão bem-sucedida", f"Reutilizando conexão com {peer_ip}:{peer_port}")

                self.setup_main_menu()

            except Exception as e:
                messagebox.showerror("Erro de conexão", f"Não foi possível conectar a {peer_ip}:{peer_port}\nErro: {e}")

    def receive_all(self, conn):
        """
        Recebe todos os dados até que não haja mais dados disponíveis.
        Isso é útil para receber a chave pública completa.
        """
        data = b''
        while True:
            part = conn.recv(4096)
            data += part
            if len(part) < 4096:
                break
        return data

    def receive_messages(self, peer):
        while True:
            try:
                encrypted_message = peer.connection.recv(4096)
                if encrypted_message:
                    # Descriptografa a mensagem recebida usando a chave privada
                    message = self.decrypt_message(encrypted_message)
                    print(f"Mensagem recebida de {peer.ip}:{peer.port}: {message}")
                    if peer.chat_window:
                        self.update_chat_window(peer, message, sender=False)
                    self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")
                else:
                    raise Exception("Conexão fechada")
            except Exception as e:
                print(f"Conexão com {peer.ip}:{peer.port} fechada: {e}")
                peer.connection.close()
                del self.peers[peer.ip]
                break

    def show_peer_list(self):
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Peers Conectados.")
        label.pack(pady=10)

        if not self.peers:
            label = tk.Label(self.current_frame, text="Nenhum peer conectado.")
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

            open_chat_button = tk.Button(self.current_frame, text="Abrir Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, peer):
        if peer.chat_window:
            peer.chat_window.lift()
            return

        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Chat com {peer.ip}:{peer.port}")
        chat_window.geometry("500x500")

        chat_text = tk.Text(chat_window, height=25, width=60, state=tk.DISABLED)
        chat_text.pack(pady=10)

        # Carregar histórico de conversa do arquivo
        self.load_chat_from_file(peer, chat_text)

        message_var = tk.StringVar()
        message_entry = tk.Entry(chat_window, textvariable=message_var, width=50)
        message_entry.pack(pady=5, padx=10, fill=tk.X)

        send_button = tk.Button(chat_window, text="Enviar", command=lambda: self.send_message(peer, message_var, chat_text))
        send_button.pack(pady=5)

        # Bind Enter key to send message
        message_entry.bind('<Return>', lambda event: self.send_message(peer, message_var, chat_text))

        peer.chat_window = chat_window

        # Exibir mensagens recebidas na janela de chat
        def on_close():
            peer.chat_window = None
            chat_window.destroy()

        chat_window.protocol("WM_DELETE_WINDOW", on_close)

    def send_message(self, peer, message_var, text_area):
        message = message_var.get()
        if message:
            message_var.set("")  # Limpa o campo de entrada

            try:
                # Criptografa a mensagem usando a chave pública do peer
                encrypted_message = self.encrypt_message(message, peer.public_key)
                peer.connection.sendall(encrypted_message)
                self.update_chat_window(peer, message, sender=True)
                self.save_chat_to_file(peer, f"Você: {message}")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível enviar a mensagem: {e}")

    def update_chat_window(self, peer, message, sender=False):
        if peer.chat_window:
            text_area = peer.chat_window.children.get('!text')
            if text_area:
                text_area.config(state=tk.NORMAL)
                if sender:
                    text_area.insert(tk.END, f"Você: {message}\n")
                else:
                    text_area.insert(tk.END, f"{peer.ip}:{peer.port}: {message}\n")
                text_area.config(state=tk.DISABLED)
                text_area.see(tk.END)

    def save_chat_to_file(self, peer, message):
        # Salva a conversa em um arquivo
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(message + '\n')

    def load_chat_from_file(self, peer, text_area):
        # Carrega o histórico de conversa de um arquivo
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                chat_history = f.read()
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, chat_history)
                text_area.config(state=tk.DISABLED)

    def encrypt_message(self, message, peer_public_key):
        # Criptografa a mensagem com a chave pública do peer
        encrypted = peer_public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decrypt_message(self, encrypted_message):
        # Descriptografa a mensagem recebida com a chave privada
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

# Função principal para iniciar o cliente-servidor
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal para perguntar porta do servidor

    # Pergunta a porta local do cliente
    local_port = simpledialog.askinteger("Porta", "Digite a porta local:")
    root.destroy()

    if local_port:
        try:
            host = socket.gethostbyname(socket.gethostname())  # Obtém o IP local
        except Exception:
            host = '127.0.0.1'  # Fallback para localhost se não conseguir obter o IP
        app = P2PChatApp(host, local_port)
        app.root.mainloop()
    else:
        messagebox.showerror("Erro", "Porta inválida. O aplicativo será encerrado.")

if __name__ == "__main__":
    start_peer()
