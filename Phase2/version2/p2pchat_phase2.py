# p2pchat_phase2.py

import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
import sys
import json
import hashlib
import secrets
import base64
import time
import uuid

# Importa primitivas criptográficas para criptografia e gerenciamento de chaves
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec  # Para troca de chaves ECDH
from cryptography.hazmat.primitives import serialization  # Para serialização de chaves
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # Para criptografia AES

# Importa módulos do Firebase Admin SDK para interação com o banco de dados
import firebase_admin
from firebase_admin import credentials, db

# Importa o AWS SDK para Python (Boto3)
import boto3
from botocore.exceptions import ClientError

import ConnectionEntity
import TkApp

if not firebase_admin._apps:
    cred = credentials.Certificate("psdproject-6e38f-firebase-adminsdk-icq10-3708af2f3d.json")
    firebase_admin.initialize_app(cred, {
        'databaseURL': 'https://psdproject-6e38f-default-rtdb.europe-west1.firebasedatabase.app/'
    })

# Diretório para armazenar a lista de peers
PEERS_DIR = "peersList"

# Cria diretórios se ainda não existirem
for directory in [PEERS_DIR]:
    if not os.path.exists(directory):
        os.makedirs(directory)

# Função para derivar uma chave AES da chave ECDH compartilhada
def derive_aes_key(shared_key):
    # Usa a função hash SHA-256 para derivar uma chave AES de 256 bits
    aes_key = hashlib.sha256(shared_key).digest()
    return aes_key

# Função para derivar uma chave AES de grupo a partir do nome do grupo
def derive_group_key(group_name):
    """
    Deriva uma chave AES de grupo a partir do nome do grupo.
    """
    group_key = hashlib.sha256(group_name.encode('utf-8')).digest()
    return group_key

# Função para sanitizar strings para caminhos do Firebase substituindo caracteres inválidos
def sanitize_for_firebase_path(s):
    # Substitui caracteres inválidos em caminhos do Firebase por underscores
    return s.replace('.', '_').replace('$', '_').replace('#', '_').replace('[', '_').replace(']', '_').replace('/', '_')

# Classe principal da Aplicação de Chat P2P
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host  # Endereço IP local
        self.port = port  # Número da porta local
        self.peers = {}  # Dicionário para armazenar peers e grupos conectados
        self.server_socket = None  # Socket do servidor para escuta
        self.messages_loaded = False  # Flag para indicar se as mensagens foram carregadas

        # Gera par de chaves ECDH para comunicação segura
        self.private_key, self.public_key = self.generate_ecdh_key_pair()
        # Serializa a chave pública para bytes para transmissão
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Inicializa o cliente S3
        self.s3 = boto3.client('s3', region_name='')  # FALTA a região AWS!!!

        # Nome do bucket S3 onde as mensagens serão armazenadas
        self.s3_bucket_name = ''  # FALTA o nome bucket S3!!!

        # Inicializa a classe TkApp com a instância root existente
        self.gui_app = TkApp.TkApp(self, host, port)        

        # Vincula o evento de fechar a janela para salvar peers antes de sair
        self.gui_app.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Inicia o servidor em uma nova thread para aceitar conexões de entrada
        threading.Thread(target=self.start_server, daemon=True).start()

        # Carrega peers do arquivo para restaurar conexões anteriores
        self.load_peers_from_file()

    def get_peers_filename(self):
        """
        Gera um nome de arquivo exclusivo para armazenar peers com base no host e na porta, dentro da pasta peersList.
        """
        sanitized_host = sanitize_for_firebase_path(self.host)
        filename = f"peers_{sanitized_host}_{self.port}.json"
        return os.path.join(PEERS_DIR, filename)

    def on_close(self):
        """
        Manipula o evento de fechar a janela para salvar peers antes de sair.
        """
        self.save_peers_to_file()
        self.gui_app.root.destroy()

    def save_peers_to_file(self):
        """
        Salva a lista de peers e grupos conectados em um arquivo JSON dentro da pasta peersList.
        """
        peers_list = []
        for key, entity in self.peers.items():
            if entity.is_group:
                peers_list.append({
                    'is_group': True,
                    'group_name': entity.group_name
                })
            else:
                peers_list.append({
                    'is_group': False,
                    'ip': entity.ip,
                    'port': entity.port
                })
        filename = self.get_peers_filename()
        with open(filename, 'w') as f:
            json.dump(peers_list, f)

    def load_peers_from_file(self):
        """
        Carrega a lista de peers e grupos conectados de um arquivo JSON dentro da pasta peersList.
        """
        filename = self.get_peers_filename()
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                peers_list = json.load(f)
            for peer_info in peers_list:
                if peer_info['is_group']:
                    group_name = peer_info['group_name']
                    if group_name not in self.peers:
                        self.connect_to_group(group_name)
                else:
                    ip = peer_info['ip']
                    port = peer_info['port']
                    # Tenta conectar ao peer se ainda não estiver conectado
                    if (ip, port) not in self.peers:
                        threading.Thread(target=self.connect_to_peer, args=(ip, port), daemon=True).start()
        else:
            print("Nenhum peer anterior para carregar.")

    def generate_ecdh_key_pair(self):
        """
        Gera um par de chaves ECDH para comunicação segura.
        """
        # Gera uma chave privada usando a curva SECP256R1
        private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        # Deriva a chave pública correspondente
        public_key = private_key.public_key()
        return private_key, public_key

    def start_server(self):
        """
        Inicia o servidor para aceitar conexões de peers.
        """
        try:
            # Cria um socket e vincula ao host e porta
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Escutando em {self.host}:{self.port}")
        except Exception as e:
            print(f"Erro ao iniciar o servidor: {e}")
            messagebox.showerror("Erro", f"Não foi possível iniciar o servidor: {e}")
            sys.exit(1)

        # Aceita continuamente conexões de entrada
        while True:
            try:
                conn, addr = self.server_socket.accept()
                peer_ip, _ = addr  # Obtém o endereço IP do peer que está se conectando

                # Inicia uma nova thread para lidar com a nova conexão
                threading.Thread(
                    target=self.handle_new_connection,
                    args=(conn, peer_ip),
                    daemon=True
                ).start()
            except Exception as e:
                print(f"Erro ao aceitar conexão: {e}")

    def handle_new_connection(self, conn, peer_ip):
        """
        Processa novas conexões recebidas de peers.
        """
        try:
            # Troca chaves públicas com o peer para troca de chaves ECDH
            peer_public_key_bytes = self.receive_all(conn)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
            print("Chave pública do peer recebida")

            # Envia a própria chave pública para o peer
            conn.sendall(self.public_key_bytes)
            print("Chave pública própria enviada")

            # Gera chave secreta compartilhada usando ECDH e deriva chave AES
            shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
            session_aes_key = derive_aes_key(shared_key)

            # Recebe o tipo de conexão e porta de escuta do peer
            msg_length_bytes = conn.recv(4)
            if not msg_length_bytes:
                raise Exception("Conexão fechada pelo peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_info = self.receive_exact(conn, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)

            # Envia o próprio tipo de conexão e porta de escuta para o peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            msg_length = len(encrypted_info)
            conn.sendall(msg_length.to_bytes(4, byteorder='big'))
            conn.sendall(encrypted_info)

            # Determina se a conexão é para um grupo ou um peer
            is_group = (connection_type == 'group')

            # Cria um ConnectionEntity para representar a conexão
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, conn, peer_public_key, session_aes_key, is_group)
            self.peers[(peer_ip, peer_listening_port)] = entity  # Usa tupla como chave
            print(f"Conectado: {peer_ip}:{peer_listening_port} como {'Grupo' if is_group else 'Peer'}")

            # Inicia uma thread para receber mensagens do peer
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()

        except Exception as e:
            print(f"Erro ao estabelecer conexão com {peer_ip}: {e}")
            conn.close()

    def connect_to_entity(self, connection_type):
        """
        Conecta a um peer ou grupo remoto usando IP e porta fornecidos pelo usuário ou nome do grupo.
        """
        if connection_type == 'peer':
            # Obtém IP e porta dos campos de entrada
            peer_ip = self.gui_app.peer_ip_entry.get()
            peer_port = self.gui_app.peer_port_entry.get()

            # Validação de entrada para IP e porta
            if not self.validate_ip(peer_ip) or not peer_port.isdigit():
                messagebox.showerror("Erro", "IP ou porta inválidos!")
                return

            peer_port = int(peer_port)

            if (peer_ip, peer_port) in self.peers:
                messagebox.showinfo("Info", f"Já está conectado a {peer_ip}:{peer_port}")
                return

            # Inicia uma thread para conectar ao peer e atualizar a interface
            threading.Thread(target=self.connect_to_peer_ui, args=(peer_ip, peer_port), daemon=True).start()

        elif connection_type == 'group':
            # Nada a fazer aqui, pois a conexão de grupo é tratada pela GUI
            pass

    def connect_to_group(self, group_name):
        """
        Conecta a um chat de grupo por nome, após verificar se o usuário tem acesso ao grupo com base em seus tópicos de interesse.
        """
        # Primeiro, obtém os tópicos de interesse do usuário do Firebase
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_data = user_ref.get()
        user_topics = user_data.get('topics', []) if user_data else []

        # Obtém o tópico do grupo do Firebase
        group_id = sanitize_for_firebase_path(group_name)
        group_ref = db.reference(f"groups/{group_id}")
        group_data = group_ref.get()
        group_topic = group_data.get('topic') if group_data else None

        if not group_topic:
            # Se o grupo ainda não existir, solicita ao usuário definir o tópico para o novo grupo
            messagebox.showinfo("Novo Grupo", f"O grupo '{group_name}' não existe. Criando um novo grupo.")
            # Solicita ao usuário selecionar um tópico para o novo grupo entre seus tópicos de interesse
            if not user_topics:
                messagebox.showerror("Erro", "Você não selecionou nenhum tópico de interesse.")
                return

            topic = simpledialog.askstring("Tópico do Grupo", "Selecione um tópico para o novo grupo:\n" + "\n".join(user_topics))
            if not topic or topic not in user_topics:
                messagebox.showerror("Erro", "Tópico inválido selecionado para o grupo.")
                return

            # Salva o tópico do grupo no Firebase
            group_ref.set({'topic': topic})
            group_topic = topic  # Define group_topic para verificação de acesso
        else:
            # Grupo já existe, tópico é conhecido
            pass

        # Verifica se o tópico do grupo está nos tópicos de interesse do usuário
        if group_topic not in user_topics:
            messagebox.showerror("Acesso Negado", f"Você não tem acesso ao grupo '{group_name}' pois não está em seus tópicos de interesse.")
            return

        # Prossegue para conectar ao grupo
        if group_name not in self.peers:
            # Cria um ConnectionEntity para o grupo com chave AES de grupo derivada
            group_aes_key = derive_group_key(group_name)
            entity = ConnectionEntity.ConnectionEntity(None, None, None, None, group_aes_key, is_group=True, group_name=group_name)
            self.peers[group_name] = entity
            # Inicia uma thread para receber mensagens do grupo
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            messagebox.showinfo("Conectado ao Grupo", f"Conectado ao grupo '{group_name}'")
            self.gui_app.setup_main_menu()
        else:
            messagebox.showinfo("Info", f"Já está conectado ao grupo '{group_name}'")

    def connect_to_peer_ui(self, peer_ip, peer_port):
        """
        Conecta a um peer e atualiza a interface de usuário adequadamente.
        """
        try:
            self.connect_to_peer(peer_ip, peer_port)
            # Informa o usuário após conexão bem-sucedida
            self.gui_app.root.after(0, lambda: messagebox.showinfo("Conexão Estabelecida", f"Conectado a {peer_ip}:{peer_port} como Peer"))
            self.gui_app.root.after(0, self.gui_app.setup_main_menu)
        except Exception as e:
            # Exibe uma mensagem de erro se a conexão falhar
            self.gui_app.root.after(0, lambda: messagebox.showerror("Erro de Conexão", f"Não foi possível conectar a {peer_ip}:{peer_port}\nErro: {e}"))

    def connect_to_peer(self, peer_ip, peer_port):
        """
        Conecta a um peer usando o IP e a porta fornecidos.
        """
        try:
            # Cria um socket e conecta ao peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            # Envia a própria chave pública para o peer
            sock.sendall(self.public_key_bytes)
            print("Chave pública própria enviada")

            # Recebe a chave pública do peer
            peer_public_key_bytes = self.receive_all(sock)
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
            print("Chave pública do peer recebida")

            # Gera chave secreta compartilhada usando ECDH e deriva chave AES
            shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
            session_aes_key = derive_aes_key(shared_key)

            # Envia o próprio tipo de conexão e porta de escuta para o peer
            my_info = f"peer,{self.port}"
            encrypted_info = self.encrypt_message(my_info, session_aes_key)
            msg_length = len(encrypted_info)
            sock.sendall(msg_length.to_bytes(4, byteorder='big'))
            sock.sendall(encrypted_info)

            # Recebe o tipo de conexão e porta de escuta do peer
            msg_length_bytes = sock.recv(4)
            if not msg_length_bytes:
                raise Exception("Conexão fechada pelo peer!")
            msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
            encrypted_info = self.receive_exact(sock, msg_length)
            info = self.decrypt_message(encrypted_info, session_aes_key)
            peer_connection_type, peer_listening_port = info.split(',')
            peer_listening_port = int(peer_listening_port)

            # Determina se o peer é um grupo ou um peer
            is_group = (peer_connection_type == 'group')

            # Cria um ConnectionEntity para representar a conexão
            entity = ConnectionEntity.ConnectionEntity(peer_ip, peer_listening_port, sock, peer_public_key, session_aes_key, is_group)
            self.peers[(peer_ip, peer_port)] = entity  # Usa tupla como chave
            # Inicia uma thread para receber mensagens do peer
            threading.Thread(target=self.receive_messages, args=(entity,), daemon=True).start()
            print(f"Conectado a {peer_ip}:{peer_port} como {'Grupo' if is_group else 'Peer'}")

        except Exception as e:
            print(f"Não foi possível conectar a {peer_ip}:{peer_port}\nErro: {e}")
            # Remove o peer da lista de peers se a conexão falhar
            if (peer_ip, peer_port) in self.peers:
                del self.peers[(peer_ip, peer_port)]
            raise

    def validate_ip(self, ip):
        """
        Valida se o IP fornecido é válido.
        """
        parts = ip.split(".")
        # Verifica se o IP consiste em quatro partes e cada parte está entre 0 e 255
        return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)

    def receive_all(self, conn):
        """
        Recebe todos os dados da conexão até não haver mais.
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
        Recebe exatamente o número especificado de bytes da conexão.
        """
        data = b''
        while len(data) < num_bytes:
            packet = conn.recv(num_bytes - len(data))
            if not packet:
                raise Exception("Conexão fechada antes de receber todos os dados!")
            data += packet
        return data

    def receive_messages(self, entity):
        """
        Recebe mensagens do peer ou grupo e atualiza a interface de chat.
        """
        if entity.is_group:
            # Para grupos, escuta mensagens dos bancos de dados em nuvem
            threading.Thread(target=self.listen_to_group_messages, args=(entity,), daemon=True).start()
        else:
            while True:
                try:
                    # Recebe o comprimento da mensagem (4 bytes)
                    msg_length_bytes = entity.connection.recv(4)
                    if not msg_length_bytes:
                        raise Exception("Conexão fechada pelo peer!")
                    msg_length = int.from_bytes(msg_length_bytes, byteorder='big')
                    # Recebe a mensagem criptografada
                    encrypted_message = self.receive_exact(entity.connection, msg_length)
                    # Descriptografa a mensagem usando a chave AES
                    message = self.decrypt_message(encrypted_message, entity.aes_key)
                    print(f"Mensagem recebida de {entity.ip}:{entity.port}: {message}")

                    # Atualiza a janela de chat se estiver aberta
                    if entity.chat_window:
                        self.gui_app.update_chat_window(entity, f"{entity.ip}:{entity.port}: {message}")
                    # Salva a mensagem nos bancos de dados em nuvem
                    self.save_chat_to_cloud(entity, f"{entity.ip}:{entity.port}", message)

                except Exception as e:
                    print(f"Conexão com {entity.ip}:{entity.port} fechada: {e}")
                    entity.connection.close()
                    # Remove o peer da lista de peers se a conexão for fechada
                    if (entity.ip, entity.port) in self.peers:
                        del self.peers[(entity.ip, entity.port)]  # Usa tupla como chave
                    break

    def listen_to_group_messages(self, group_entity):
        """
        Escuta mensagens do grupo nos bancos de dados em nuvem.
        """
        group_id = sanitize_for_firebase_path(group_entity.group_name)
        group_ref = db.reference(f"groups/{group_id}/messages")

        def listener(event):
            # Listener de eventos para novas mensagens no grupo
            if event.data and event.event_type == 'put':
                # Verifica se o evento é para uma nova mensagem
                if event.path != '/':
                    message_data = event.data
                    # Decodifica a mensagem de base64 e descriptografa
                    encrypted_message_b64 = message_data.get('message', '')
                    if encrypted_message_b64:
                        encrypted_message = base64.b64decode(encrypted_message_b64)
                        try:
                            message = self.decrypt_message(encrypted_message, group_entity.aes_key)
                        except Exception as e:
                            print(f"Falha ao descriptografar mensagem: {e}")
                            return
                        sender = message_data.get('sender', '')
                        if sender != f"{self.host}:{self.port}":
                            if group_entity.chat_window:
                                display_message = f"{sender}: {message}"
                                self.gui_app.update_chat_window(group_entity, display_message)

        # Inicia a escuta das mensagens do grupo
        group_ref.listen(listener)

    def send_message(self, entity, message_var):
        """
        Envia uma mensagem ao peer ou grupo usando criptografia AES.
        """
        message = message_var.get()
        if message:
            message_var.set("")  # Limpa o campo de entrada

            try:
                if entity.is_group:
                    # Para grupos, criptografa a mensagem e envia aos bancos de dados em nuvem
                    self.save_chat_to_cloud(entity, f"{self.host}:{self.port}", message)
                else:
                    # Para peers, envia a mensagem diretamente pelo socket
                    encrypted_message = self.encrypt_message(message, entity.aes_key)
                    msg_length = len(encrypted_message)
                    entity.connection.sendall(msg_length.to_bytes(4, byteorder='big'))
                    entity.connection.sendall(encrypted_message)
                    print("Mensagem enviada")
                    # Salva a mensagem nos bancos de dados em nuvem
                    self.save_chat_to_cloud(entity, f"Você", message)

                # Atualiza a janela de chat com a mensagem enviada
                self.gui_app.update_chat_window(entity, f"Você: {message}")
            except Exception as e:
                messagebox.showerror("Erro", f"Não foi possível enviar a mensagem: {e}")

    def save_chat_to_cloud(self, entity, sender, message):
        """
        Salva a conversa nos bancos de dados em nuvem.
        """
        # Criptografa a mensagem antes de armazenar
        encrypted_message = self.encrypt_message(message, entity.aes_key)
        # Converte a mensagem criptografada para base64 para armazenar como string
        encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')

        # Prepara os dados para serem armazenados
        data = {
            'sender': sender,
            'message': encrypted_message_b64,
            'timestamp': int(time.time()),
            'id': str(uuid.uuid4())
        }

        if entity.is_group:
            # Salva mensagens na referência do grupo no Firebase
            group_id = sanitize_for_firebase_path(entity.group_name)
            group_ref = db.reference(f"groups/{group_id}/messages")
            group_ref.push(data)
            # Também salva no AWS S3
            self.save_message_to_s3(entity, data)
        else:
            # Salva mensagens na referência do chat no Firebase
            chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_ref = db.reference(f"chats/{chat_id}")
            chat_ref.push(data)
            # Também salva no AWS S3
            self.save_message_to_s3(entity, data)

    def save_message_to_s3(self, entity, data):
        """
        Salva a mensagem no Amazon S3.
        """
        # Converte a mensagem para JSON e nomeia o arquivo com um UUID único
        message_id = data['id']
        if entity.is_group:
            object_key = f"groups/{sanitize_for_firebase_path(entity.group_name)}/{message_id}.json"
        else:
            object_key = f"peers/{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}/{message_id}.json"
        
        # Cria o conteúdo JSON para o S3
        content = json.dumps(data).encode('utf-8')
        
        try:
            # Envia o conteúdo para o bucket S3
            self.s3.put_object(Bucket=self.s3_bucket_name, Key=object_key, Body=content)
            print(f"Mensagem {message_id} salva no S3 com sucesso.")
        except ClientError as e:
            print(f"Erro ao salvar mensagem no S3: {e}")

    def encrypt_message(self, message, aes_key):
        """
        Criptografa a mensagem usando AES no modo GCM.
        """
        nonce = secrets.token_bytes(12)  # Gera um nonce aleatório
        # Cria um objeto de criptografia AES-GCM
        encryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend()).encryptor()
        # Criptografa a mensagem
        ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
        # Retorna a concatenação de nonce, ciphertext e tag
        return nonce + ciphertext + encryptor.tag

    def decrypt_message(self, encrypted_message, aes_key):
        """
        Descriptografa a mensagem usando AES no modo GCM.
        """
        nonce = encrypted_message[:12]  # Extrai o nonce
        tag = encrypted_message[-16:]  # Extrai a tag
        ciphertext = encrypted_message[12:-16]  # Extrai o ciphertext
        # Cria um objeto de descriptografia AES-GCM
        decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
        # Descriptografa o ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')

    def perform_privacy_preserving_search(self, keywords):
        """
        Pesquisa todos os peers/grupos conectados por mensagens contendo as palavras-chave usando ORAM.
        """
        results = []

        # Coleta todas as mensagens em uma lista
        all_messages = []

        # Garante que as mensagens estão carregadas
        self.load_all_messages()

        # Para cada entidade conectada, recupera as mensagens em cache
        for entity_key, entity in self.peers.items():
            if entity.messages:
                # Simula ORAM embaralhando as mensagens
                import random
                random.shuffle(entity.messages)

                for msg in entity.messages:
                    message = msg['message']
                    if any(keyword.lower() in message.lower() for keyword in keywords):
                        if entity.is_group:
                            results.append(f"Grupo '{entity.group_name}', Mensagem: {message}")
                        else:
                            results.append(f"Peer {entity.ip}:{entity.port}, Mensagem: {message}")
                    else:
                        # Operação dummy para simular padrão de acesso ORAM
                        pass  # Não faz nada

        return results

    def load_all_messages(self):
        """
        Carrega mensagens de todos os peers e grupos conectados na memória.
        """
        if self.messages_loaded:
            return  # As mensagens já estão carregadas

        for entity_key, entity in self.peers.items():
            entity.messages = []
            messages = self.load_messages_from_cloud(entity)
            entity.messages.extend(messages)

        self.messages_loaded = True  # Define a flag para indicar que as mensagens estão carregadas

    def load_messages_from_cloud(self, entity):
        """
        Carrega mensagens do Firebase e do Amazon S3 para uma dada entidade.
        """
        messages = []

        # Carrega mensagens do Firebase
        firebase_messages = self.load_messages_from_firebase(entity)
        messages.extend(firebase_messages)

        # Carrega mensagens do S3
        s3_messages = self.load_messages_from_s3(entity)
        messages.extend(s3_messages)

        # Remove duplicatas com base no ID da mensagem
        messages_dict = {}
        for msg in messages:
            messages_dict[msg['id']] = msg
        messages = list(messages_dict.values())

        # Ordena mensagens por timestamp
        messages = sorted(messages, key=lambda x: x['timestamp'])

        return messages

    def load_messages_from_firebase(self, entity):
        """
        Carrega mensagens do Firebase para uma dada entidade.
        """
        messages = []
        if entity.is_group:
            # Carrega mensagens da referência do grupo no Firebase
            group_id = sanitize_for_firebase_path(entity.group_name)
            group_ref = db.reference(f"groups/{group_id}/messages")
            messages_data = group_ref.get()
        else:
            # Carrega mensagens da referência do chat no Firebase
            chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_ref = db.reference(f"chats/{chat_id}")
            messages_data = chat_ref.get()

        if messages_data:
            for msg_key in messages_data:
                message_data = messages_data[msg_key]
                # Descriptografa a mensagem
                encrypted_message_b64 = message_data.get('message', '')
                if encrypted_message_b64:
                    encrypted_message = base64.b64decode(encrypted_message_b64)
                    try:
                        message = self.decrypt_message(encrypted_message, entity.aes_key)
                    except Exception as e:
                        print(f"Falha ao descriptografar mensagem: {e}")
                        continue
                    message_data['message'] = message
                    messages.append(message_data)

        return messages

    def load_messages_from_s3(self, entity):
        """
        Carrega mensagens do Amazon S3 para uma dada entidade.
        """
        messages = []
        try:
            if entity.is_group:
                prefix = f"groups/{sanitize_for_firebase_path(entity.group_name)}/"
            else:
                prefix = f"peers/{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}/"

            # Lista os objetos no bucket S3 relacionados ao peer/grupo
            response = self.s3.list_objects_v2(Bucket=self.s3_bucket_name, Prefix=prefix)
            
            if 'Contents' in response:
                for obj in response['Contents']:
                    # Baixa cada objeto e carrega o conteúdo
                    object_key = obj['Key']
                    object_data = self.s3.get_object(Bucket=self.s3_bucket_name, Key=object_key)
                    message_data = json.loads(object_data['Body'].read().decode('utf-8'))

                    # Descriptografa a mensagem
                    encrypted_message_b64 = message_data.get('message', '')
                    if encrypted_message_b64:
                        encrypted_message = base64.b64decode(encrypted_message_b64)
                        try:
                            message = self.decrypt_message(encrypted_message, entity.aes_key)
                        except Exception as e:
                            print(f"Falha ao descriptografar mensagem: {e}")
                            continue
                        message_data['message'] = message
                        messages.append(message_data)
        except ClientError as e:
            print(f"Erro ao carregar mensagens do S3: {e}")

        return messages

    def get_recommendations(self):
        """
        Analisa o histórico de mensagens do cliente para determinar tópicos e grupos recomendados.
        """
        # Coleta todas as mensagens enviadas pelo cliente
        user_id = f"{self.host}:{self.port}"
        messages = []

        # Carrega mensagens de todas as entidades conectadas
        self.load_all_messages()

        # Percorre todas as mensagens em cache
        for entity_key, entity in self.peers.items():
            if entity.messages:
                for msg in entity.messages:
                    sender = msg.get('sender', '')
                    message = msg.get('message', '')
                    if sender == user_id or sender == 'Você':
                        messages.append(message)

        # Agora analisa as mensagens para extrair tópicos
        topics_keywords = {
            'Carros': ['carro', 'automóvel', 'veículo', 'dirigir'],
            'Música': ['música', 'canção', 'álbum', 'banda', 'artista'],
            'Futebol': ['futebol', 'gol', 'partida', 'jogador'],
            'Basquete': ['basquete', 'nba', 'enterrar', 'jogador'],
            'Cibersegurança': ['cibersegurança', 'hacking', 'segurança', 'malware', 'criptografia'],
            'IA-Inteligência Artificial': ['ia', 'inteligência artificial', 'aprendizado de máquina', 'rede neural'],
            'IoT-Internet das Coisas': ['iot', 'internet das coisas', 'dispositivo inteligente', 'sensor', 'conectividade']
        }

        topics_count = {}

        for message in messages:
            message_lower = message.lower()
            for topic, keywords in topics_keywords.items():
                for keyword in keywords:
                    if keyword in message_lower:
                        topics_count[topic] = topics_count.get(topic, 0) + 1

        # Agora obtém os tópicos ordenados por contagem
        recommended_topics = sorted(topics_count.items(), key=lambda item: item[1], reverse=True)

        # Agora obtém os grupos relacionados a esses tópicos
        groups_ref = db.reference("groups")
        groups_data = groups_ref.get()
        recommended_groups = []

        if groups_data:
            for group_name, group_info in groups_data.items():
                group_topic = group_info.get('topic')
                for topic, _ in recommended_topics:
                    if group_topic == topic:
                        recommended_groups.append((group_name, group_topic))
                        break

        # Retorna os tópicos e grupos recomendados
        return recommended_topics, recommended_groups

# Função principal para iniciar o cliente-servidor
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal para solicitar a porta do servidor

    # Solicita ao usuário inserir a porta local
    local_port = simpledialog.askinteger("Porta", "Insira a porta local:")
    root.destroy()

    if local_port:
        try:
            # Obtém o endereço IP local
            host = socket.gethostbyname(socket.gethostname())
        except Exception:
            host = '127.0.0.1'  # Volta para localhost se não conseguir obter o IP
        # Inicializa a Aplicação de Chat P2P
        app = P2PChatApp(host, local_port)
        app.gui_app.root.mainloop()
    else:
        messagebox.showerror("Erro", "Porta inválida! A aplicação será encerrada.")

# Função principal para iniciar a aplicação GUI
if __name__ == "__main__":
    start_peer()
