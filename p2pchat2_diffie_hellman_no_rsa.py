import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
import datetime
import secrets
import hashlib

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


# Função para configurar a chave AES usando Diffie-Hellman
def configure_aes_key(derived_key):
    # Derivar uma chave AES de 256 bits a partir da chave DH (normalmente 256 bits SHA-256)
    return derived_key[:32]  # Usar os primeiros 32 bytes como chave AES

# Diretório para armazenar os certificados e chaves
CERT_DIR = "certificates"
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

# Caminho para o ficheiro ACL que armazena os peers confiáveis
ACL_FILE = "trusted_peers.json"

# Função para realizar a troca de chaves Diffie-Hellman
def perform_dh_key_exchange(peer_public_key, private_key):
    # Gerar a chave partilhada com o peer usando a chave pública e privada
    shared_key = private_key.exchange(peer_public_key)
    
    # Derivar a chave final a partir da chave partilhada
    derived_key = hashlib.sha256(shared_key).digest()
    aes_key = configure_aes_key(derived_key)
    
    return aes_key

def exchange_dh_keys(connection, private_key):
    """
    Exchange Diffie-Hellman public keys with the peer.
    """
    # Send our public key
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    connection.sendall(public_key_bytes)

    # Receive the peer's public key
    peer_public_key_bytes = connection.recv(1024)  # Adjust buffer size if necessary
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

    return peer_public_key


# Classe que representa um Peer conectado
class Peer:
    def __init__(self, ip, port, connection, certificate, aes_key, dh_private_key=None, dh_public_key=None):
        self.ip = ip
        self.port = port
        self.connection = connection
        self.certificate = certificate  # Certificado x509 do peer
        self.aes_key = aes_key  # Chave AES para comunicação segura
        self.dh_private_key = dh_private_key  # DH private key
        self.dh_public_key = dh_public_key    # DH public key
        self.chat_window = None  # Janela de chat associada ao peer


# Classe principal da aplicação P2P
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.peers = {}  # Dicionário para armazenar os peers conectados
        self.server_socket = None  # Socket do servidor

        # Carrega ou gera o par de chaves e o certificado
        self.private_key, self.certificate = self.load_or_generate_certificate()
        self.certificate_bytes = self.certificate.public_bytes(serialization.Encoding.PEM)

        # Carrega a ACL (Access Control List)
        self.trusted_peers = self.load_acl()

        # Inicia a interface gráfica
        self.root = tk.Tk()
        self.root.title(f"Client/Server: {host}:{port}")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)

        self.current_frame = None
        self.setup_main_menu()

        # Inicia o servidor numa nova thread para permitir a execução simultânea
        threading.Thread(target=self.start_server, daemon=True).start() 

    def load_or_generate_certificate(self):
        """
        Carrega ou gera um par de chaves RSA e um certificado autoassinado.
        """
        cert_path = os.path.join(CERT_DIR, f"peer_{self.port}.pem")
        key_path = os.path.join(CERT_DIR, f"peer_{self.port}_key.pem")
        
        if os.path.exists(cert_path) and os.path.exists(key_path):
            # Carrega chaves e certificado se já existirem
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
            with open(cert_path, "rb") as cert_file:
                certificate = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
            return private_key, certificate
        else:
            # Gera um novo par de chaves RSA
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            public_key = private_key.public_key()

            # Gera um certificado autoassinado para o peer
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, f"Peer_{self.port}")
            ])
            certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                public_key
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                # Certificado válido por 10 anos
                datetime.datetime.utcnow() + datetime.timedelta(days=3650)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(f"Peer_{self.port}")]),
                critical=False
            ).sign(private_key, hashes.SHA256(), default_backend())

            # Salva as chaves e o certificado
            with open(key_path, "wb") as key_file:
                key_file.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            with open(cert_path, "wb") as cert_file:
                cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))
            
            return private_key, certificate

    def load_acl(self):
        """
        Carrega a lista de peers confiáveis (ACL) a partir de um ficheiro JSON.
        """
        if os.path.exists(ACL_FILE):
            with open(ACL_FILE, "r") as f:
                return json.load(f)
        else:
            return []

    def save_acl(self):
        """
        Salva a lista de peers confiáveis no ficheiro ACL.
        """
        with open(ACL_FILE, "w") as f:
            json.dump(self.trusted_peers, f, indent=4)

    def setup_main_menu(self):
        """
        Configura o menu principal da interface gráfica.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        self.info_label = tk.Label(self.current_frame, text=f"Seu IP: {self.host}\nSua Porta: {self.port}")
        self.info_label.pack(pady=10)

        self.connect_button = tk.Button(self.current_frame, text="Conectar a um novo peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        self.list_button = tk.Button(self.current_frame, text="Lista de Peers", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    def show_connection_inputs(self):
        """
        Mostra os campos de entrada para conectar a um novo peer.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="IP do Peer:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.current_frame, text="Porta do Peer:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        self.connect_peer_button = tk.Button(self.current_frame, text="Conectar", command=self.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def clear_frame(self):
        """
        Limpa o frame atual para carregar novos widgets.
        """
        for widget in self.current_frame.winfo_children():
            widget.destroy()

    def start_server(self):
        """
        Inicia o servidor para aceitar conexões de peers.
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"A ouvir em {self.host}:{self.port}")
        except Exception as e:
            print(f"Erro ao iniciar o servidor: {e}")
            messagebox.showerror("Erro", f"Não foi possível iniciar o servidor: {e}")
            sys.exit(1)

        while True:
            try:
                conn, addr = self.server_socket.accept()
                peer_ip, peer_port = addr

                threading.Thread(
                    target=self.handle_new_connection, 
                    args=(conn, peer_ip, peer_port), 
                    daemon=True
                ).start()
            except Exception as e:
                print(f"Erro ao aceitar conexão: {e}")

    def handle_new_connection(self, conn, peer_ip, peer_port):
        """
        Processa novas conexões recebidas pelos peers.
        """
        try:
            # Troca de certificados
            peer_cert_bytes = self.receive_all(conn)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            print("Recebe certificado")

            # Envia o próprio certificado
            conn.sendall(self.certificate_bytes)
            print("Envia certificado")

            # Receive peer's DH public key
            peer_dh_public_key_bytes = self.receive_all(conn)  
            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())
            
            print(f"Received peer DH public key size: {len(peer_dh_public_key_bytes)} bytes") 
            
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            dh_private_key = parameters.generate_private_key()
            dh_public_key = dh_private_key.public_key()            
            
            print("Gera par chaves")            

            # Send DH public key to peer
            dh_public_key_bytes = dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            conn.sendall(dh_public_key_bytes)
            print(f"Sent DH public key size: {len(dh_public_key_bytes)} bytes")      

            # Derive AES key from shared DH key
            shared_key = dh_private_key.exchange(peer_dh_public_key)
            print("Cria shared key")
            aes_key = hashlib.sha256(shared_key).digest()[:32]

            peer = Peer(peer_ip, peer_port, conn, peer_certificate, aes_key, dh_private_key)
            self.peers[peer_ip] = peer
            print(f"Peer confiável conectado: {peer_ip}:{peer_port}")
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            
        
        except Exception as e:
            print(f"Erro ao estabelecer conexão com {peer_ip}:{peer_port}: {e}")
            conn.close()

    def connect_to_peer(self):
        """
        Conecta a um peer remoto utilizando IP e porta fornecidos pelo utilizador.
        """
        peer_ip = self.peer_ip_entry.get()
        peer_port = self.peer_port_entry.get()

        # Validação de entradas
        if not self.validate_ip(peer_ip) or not peer_port.isdigit():
            messagebox.showerror("Erro", "IP ou porta inválidos!")
            return

        peer_port = int(peer_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Envia o próprio certificado
            sock.sendall(self.certificate_bytes)
            print("Envia certificado")

            # Recebe o certificado do peer
            peer_cert_bytes = self.receive_all(sock)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            print("Recebe certificado")
            
            parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
            dh_private_key = parameters.generate_private_key()
            dh_public_key = dh_private_key.public_key() 
            
            print("Gera par chaves")            

            # Send the public DH key to the peer
            dh_public_key_bytes = dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(dh_public_key_bytes)
            
            # After sending DH public key
            print(f"Sent DH public key size: {len(dh_public_key_bytes)} bytes")

            # Receive the peer's DH public key
            peer_dh_public_key_bytes = self.receive_all(sock)

            print(f"Received peer DH public key size: {len(peer_dh_public_key_bytes)} bytes")            

            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())

            # Perform key exchange and derive shared AES key
            shared_key = dh_private_key.exchange(peer_dh_public_key)
            print("Cria shared key")
            aes_key = hashlib.sha256(shared_key).digest()[:32]  # Derive AES key from shared secret

            peer = Peer(peer_ip, peer_port, sock, peer_certificate, aes_key)
            self.peers[peer_ip] = peer
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            messagebox.showinfo("Conexão bem-sucedida", f"Conectado e confiável {peer_ip}:{peer_port}")

            self.setup_main_menu()

        except Exception as e:
            messagebox.showerror("Erro de conexão", f"Não foi possível conectar a {peer_ip}:{peer_port}\nErro: {e}")

    def validate_ip(self, ip):
        """
        Valida se o IP fornecido é válido.
        """
        parts = ip.split(".")
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def receive_all(self, conn):
        """
        Recebe todos os dados da conexão até que não haja mais.
        """
        data = b''
        while True:
            part = conn.recv(4096)
            if not part:
                break
            data += part
            if len(part) < 4096:
                break
        return data

    def receive_aes_key(self, conn):
        """
        Recebe e desencripta a chave AES enviada pelo peer.
        """
        encrypted_aes_key_length_bytes = self.receive_exact(conn, 4)
        encrypted_aes_key_length = int.from_bytes(encrypted_aes_key_length_bytes, byteorder='big')
        encrypted_aes_key = self.receive_exact(conn, encrypted_aes_key_length)
        return self.decrypt_aes_key(encrypted_aes_key)

    def receive_exact(self, conn, num_bytes):
        """
        Recebe exatamente o número de bytes especificado da conexão.
        """
        data = b''
        while len(data) < num_bytes:
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                raise Exception("Conexão fechada antes de receber todos os dados!")
            data += packet
        return data

    def decrypt_aes_key(self, encrypted_aes_key):
        """
        Desencripta a chave AES usando a chave privada RSA.
        """
        decrypted_aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_aes_key

    def generate_aes_key(self):
        """
        Gera uma chave AES de 256 bits.
        """
        return secrets.token_bytes(32)

    def receive_messages(self, peer):
        """
        Recebe mensagens do peer e atualiza a interface de chat.
        """
        while True:
            try:
                msg_length_bytes = peer.connection.recv(4)
                if not msg_length_bytes:
                    raise Exception("Conexão fechada pelo peer!")
                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                encrypted_message = self.receive_exact(peer.connection, msg_length)
                message = self.decrypt_message(encrypted_message, peer.aes_key)
                print(f"Mensagem recebida de {peer.ip}:{peer.port}: {message}")

                if peer.chat_window:
                    self.update_chat_window(peer, message, sender=False)
                self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")

            except Exception as e:
                print(f"Conexão com {peer.ip}:{peer.port} fechada: {e}")
                peer.connection.close()
                del self.peers[peer.ip]
                break

    def show_peer_list(self):
        """
        Exibe a lista de peers conectados.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Peers Conectados")
        label.pack(pady=10)

        if not self.peers:
            label = tk.Label(self.current_frame, text="Nenhum peer conectado")
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
        """
        Abre uma janela de chat para comunicação com o peer.
        """
        if peer.chat_window:
            peer.chat_window.lift()
            return

        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Chat com {peer.ip}:{peer.port}")
        chat_window.geometry("500x500")

        chat_text = tk.Text(chat_window, height=25, width=60, state=tk.DISABLED)
        chat_text.pack(pady=10)

        self.load_chat_from_file(peer, chat_text)

        message_var = tk.StringVar()
        message_entry = tk.Entry(chat_window, textvariable=message_var, width=50)
        message_entry.pack(pady=5, padx=10, fill=tk.X)

        send_button = tk.Button(chat_window, text="Enviar", command=lambda: self.send_message(peer, message_var, chat_text))
        send_button.pack(pady=5)

        message_entry.bind('<Return>', lambda event: self.send_message(peer, message_var, chat_text))

        peer.chat_window = chat_window

        def on_close():
            peer.chat_window = None
            chat_window.destroy()

        chat_window.protocol("WM_DELETE_WINDOW", on_close)

    def send_message(self, peer, message_var, text_area):
        """
        Envia uma mensagem para o peer usando encriptação AES.
        """
        message = message_var.get()
        if message:
            message_var.set("")  # Limpa o campo de entrada

            try:
                encrypted_message = self.encrypt_message(message, peer.aes_key)
                msg_length = len(encrypted_message)
                peer.connection.sendall(msg_length.to_bytes(4, byteorder='big'))
                peer.connection.sendall(encrypted_message)

                self.update_chat_window(peer, message, sender=True)
                self.save_chat_to_file(peer, f"Você: {message}")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível enviar a mensagem: {e}")

    def update_chat_window(self, peer, message, sender=False):
        """
        Atualiza a janela de chat com novas mensagens.
        """
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
        """
        Salva a conversa num ficheiro de histórico.
        """
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(message + '\n')

    def load_chat_from_file(self, peer, text_area):
        """
        Carrega o histórico de conversa a partir de um ficheiro.
        """
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                chat_history = f.read()
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, chat_history)
                text_area.config(state=tk.DISABLED)

    def encrypt_message(self, message, aes_key):
        """
        Criptografa a mensagem usando AES em modo GCM para garantir integridade e confidencialidade.
        Retorna o nonce concatenado com o ciphertext e o tag.
        """
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, encrypted_message, aes_key):
        """
        Descriptografa a mensagem usando AES em modo GCM.
        Espera que a mensagem esteja no formato nonce + ciphertext + tag.
        """
        nonce = encrypted_message[:12]
        tag = encrypted_message[-16:]
        ciphertext = encrypted_message[12:-16]
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext.decode('utf-8')


# Função principal para iniciar o cliente-servidor
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal para perguntar porta do servidor

    local_port = simpledialog.askinteger("Porta", "Insira a porta local:")
    root.destroy()

    if local_port:
        try:
            host = socket.gethostbyname(socket.gethostname())  # Obtém o IP local
        except Exception:
            host = '127.0.0.1'  # Fallback para localhost se não conseguir obter o IP
        app = P2PChatApp(host, local_port)
        app.root.mainloop()
    else:
        messagebox.showerror("Erro", "Porta inválida! A aplicação será encerrada.")

if __name__ == "__main__":
    start_peer()
