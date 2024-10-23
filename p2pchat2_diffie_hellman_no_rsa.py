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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
import secrets
from cryptography.hazmat.primitives.asymmetric import ec

# Diretório para armazenar os certificados e chaves
CERT_DIR = "certificates"
if not os.path.exists(CERT_DIR):
    os.makedirs(CERT_DIR)

# Caminho para o ficheiro ACL que armazena os peers confiáveis
ACL_FILE = "trusted_peers.json"


def configure_aes_key(shared_key):
    # Deriva uma chave AES de 256 bits a partir da shared key
    aes_key = hashlib.sha256(shared_key).digest()[:32]  # Usa os primeiros 32 bytes como chave AES
    return aes_key

def generate_key_pair():

        dh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

        return dh_private_key.public_key(), dh_private_key  

# Classe de Peer ligado
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
        self.peers = {}  # Dicionário para armazenar os peers ligados
        self.server_socket = None  # Socket do servidor

        # Carrega/gera o par de chaves e o certificado
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
        Carrega ou gera um par de chaves DH e um certificado autoassinado.
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
            
            public_key, private_key = generate_key_pair()

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

            # Guarda as chaves e o certificado
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
        Guarda a lista de peers confiáveis no ficheiro ACL.
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

        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        self.connect_button = tk.Button(self.current_frame, text="Connect to a peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        self.list_button = tk.Button(self.current_frame, text="Peers List", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    def show_connection_inputs(self):
        """
        Mostra os campos de entrada para ligar a um novo peer.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Peer IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.current_frame, text="Peer Port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        self.connect_peer_button = tk.Button(self.current_frame, text="Connect", command=self.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def clear_frame(self):
        """
        Limpa o frame atual para carregar os novos widgets.
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
            print(f"Error starting server: {e}")
            messagebox.showerror("Error", f"Unable to start server: {e}")
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
                print(f"Error accepting connection: {e}")

    def handle_new_connection(self, conn, peer_ip, peer_port):
        """
        Processa novas conexões recebidas pelos peers.
        """
        try:
            # Troca de certificados
            peer_cert_bytes = self.receive_all(conn)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())

            # Envia o próprio certificado
            conn.sendall(self.certificate_bytes)
            # Recebe a chave publica ECDH do outro peer
            peer_dh_public_key_bytes = self.receive_all(conn)  
            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())
            
            self.dh_public_key, self.dh_private_key = generate_key_pair()

            # Envia a chave pública ECDH do outro peer
            dh_public_key_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )   
            conn.sendall(dh_public_key_bytes)     
            
            shared_key = self.dh_private_key.exchange(ec.ECDH(), peer_dh_public_key)
            aes_key = configure_aes_key(shared_key)

            peer = Peer(peer_ip, peer_port, conn, peer_certificate, aes_key, self.dh_private_key)
            self.peers[peer_ip] = peer
            print(f"Trusted Peer Connected: {peer_ip}:{peer_port}")
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            
        
        except Exception as e:
            print(f"Error establishing connection with {peer_ip}:{peer_port}: {e}")
            conn.close()

    def connect_to_peer(self):
        """
        Conecta a um peer remoto utilizando IP e porta fornecidos pelo utilizador.
        """
        peer_ip = self.peer_ip_entry.get()
        peer_port = self.peer_port_entry.get()

        # Validação do ip
        if not self.validate_ip(peer_ip) or not peer_port.isdigit():
            messagebox.showerror("Error", "Invalid IP or port!")
            return

        peer_port = int(peer_port)

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Envia o próprio certificado
            sock.sendall(self.certificate_bytes)

            # Recebe o certificado do peer
            peer_cert_bytes = self.receive_all(sock)
            peer_certificate = x509.load_pem_x509_certificate(peer_cert_bytes, default_backend())
            
            self.dh_public_key, self.dh_private_key = generate_key_pair()                            

            # Envia a chave pública ECDH ao outro peer
            dh_public_key_bytes = self.dh_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(dh_public_key_bytes)

            # Recebe a chave pública ECDH do outro peer
            peer_dh_public_key_bytes = self.receive_all(sock)            

            peer_dh_public_key = serialization.load_pem_public_key(peer_dh_public_key_bytes, backend=default_backend())

            shared_key = self.dh_private_key.exchange(ec.ECDH(), peer_dh_public_key)
                        
            aes_key = configure_aes_key(shared_key)

            peer = Peer(peer_ip, peer_port, sock, peer_certificate, aes_key)
            self.peers[peer_ip] = peer
            threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
            messagebox.showinfo("Connection well-established", f"Connected & trusted {peer_ip}:{peer_port}")

            self.setup_main_menu()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to {peer_ip}:{peer_port}\nError: {e}")

    def validate_ip(self, ip):
        """
        Função secundária que verifica se o IP fornecido é válido.
        """
        parts = ip.split(".")
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def receive_all(self, conn):
        """
        Função secundária que recebe todos os dados conexão.
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

    def receive_exact(self, conn, num_bytes):
        """
        Função secundária que recebe exatamente o número de bytes especificado da conexão.
        """
        data = b''
        while len(data) < num_bytes:
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                raise Exception("Connection closed before receiving all data!")
            data += packet
        return data

    def decrypt_aes_key(self, encrypted_aes_key):
        """
        Desencripta a chave AES usando a chave privada ECDH.
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

    def receive_messages(self, peer):
        """
        Recebe mensagens do peer e atualiza a interface do chat.
        """
        while True:
            try:
                msg_length_bytes = peer.connection.recv(4)
                if not msg_length_bytes:
                    raise Exception("Connection closed by peer!")
                msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                encrypted_message = self.receive_exact(peer.connection, msg_length)
                message = self.decrypt_message(encrypted_message, peer.aes_key)

                if peer.chat_window:
                    self.update_chat_window(peer, message, sender=False)
                self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")

            except Exception as e:
                print(f"Connection to {peer.ip}:{peer.port} closed: {e}")
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

        label = tk.Label(self.current_frame, text="Peers Conneceted")
        label.pack(pady=10)

        if not self.peers:
            label = tk.Label(self.current_frame, text="No peer connected")
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
        """
        Abre uma janela de chat para comunicação com o peer.
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

        send_button = tk.Button(chat_window, text="Send", command=lambda: self.send_message(peer, message_var, chat_text))
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
                self.save_chat_to_file(peer, f"You: {message}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not send message: {e}")

    def update_chat_window(self, peer, message, sender=False):
        """
        Atualiza a janela de chat com novas mensagens.
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

    local_port = simpledialog.askinteger("Port", "Insert local port:")
    root.destroy()

    if local_port:
        try:
            host = socket.gethostbyname(socket.gethostname())  # Obtém o IP local
        except Exception:
            host = '127.0.0.1'  # Fallback para localhost se não conseguir obter o IP
        app = P2PChatApp(host, local_port)
        app.root.mainloop()
    else:
        messagebox.showerror("Error", "Invalid port! Application will now end.")

if __name__ == "__main__":
    start_peer()
