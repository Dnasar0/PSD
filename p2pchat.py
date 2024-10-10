import socket
import threading
import tkinter as tk
from tkinter import simpledialog, messagebox
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Classe que representa um peer na rede P2P
class Peer:
    def __init__(self, ip, port, connection, public_key):
        self.ip = ip  # Endereço IP do peer
        self.port = port  # Porta do peer
        self.connection = connection  # Objeto de conexão (socket)
        self.public_key = public_key  # Chave pública do peer
        self.chat_window = None  # Janela de chat associada a este peer

# Classe principal da aplicação de chat P2P
class P2PChatApp:
    def __init__(self, host, port):
        self.host = host  # Endereço IP local
        self.port = port  # Porta local
        self.peers = {}  # Dicionário para armazenar os peers conectados
        self.server_socket = None  # Socket do servidor

        # Geração do par de chaves RSA para encriptação
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        # Serialização da chave pública para envio através da rede
        self.public_key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Inicialização da interface gráfica com Tkinter
        self.root = tk.Tk()
        self.root.title(f"Client/Server: {host}:{port}")  # Título da janela com IP e porta
        self.root.geometry("500x500")  # Define o tamanho inicial da janela
        self.root.minsize(500, 500)  # Define o tamanho mínimo da janela

        self.current_frame = None  # Frame atual na interface
        self.setup_main_menu()  # Configura o menu principal

        # Inicia o servidor numa nova thread para ouvir conexões entrantes
        threading.Thread(target=self.start_server, daemon=True).start()

    # Configura o menu principal da aplicação
    def setup_main_menu(self):
        if self.current_frame:
            self.current_frame.destroy()  # Remove o frame atual se existir

        self.current_frame = tk.Frame(self.root)  # Cria um novo frame
        self.current_frame.pack(pady=20)  # Adiciona padding vertical

        # Label que mostra o IP e a porta do utilizador
        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        # Botão para conectar a um novo peer
        self.connect_button = tk.Button(self.current_frame, text="Connect to a new peer", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        # Botão para listar os peers conectados
        self.list_button = tk.Button(self.current_frame, text="Peer List", command=self.show_peer_list)
        self.list_button.pack(pady=10)

    # Mostra os inputs para inserir IP e porta do peer a conectar
    def show_connection_inputs(self):
        self.clear_frame()  # Limpa o frame atual

        # Label e campo de entrada para o IP do peer
        tk.Label(self.current_frame, text="Peer IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.current_frame)
        self.peer_ip_entry.pack(pady=5)

        # Label e campo de entrada para a porta do peer
        tk.Label(self.current_frame, text="Peer port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.current_frame)
        self.peer_port_entry.pack(pady=5)

        # Botão para efetuar a conexão
        self.connect_peer_button = tk.Button(self.current_frame, text="Connect", command=self.connect_to_peer)
        self.connect_peer_button.pack(pady=10)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    # Limpa todos os widgets do frame atual
    def clear_frame(self):
        for widget in self.current_frame.winfo_children():
            widget.destroy()

    # Inicia o servidor para aceitar conexões entrantes
    def start_server(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Cria um socket TCP
        self.server_socket.bind((self.host, self.port))  # Liga o socket ao endereço IP e porta
        self.server_socket.listen(5)  # Escuta até 5 conexões pendentes
        print(f"Listening on {self.host}:{self.port}")  # Mensagem no terminal

        while True:
            conn, addr = self.server_socket.accept()  # Aceita uma nova conexão
            peer_ip, peer_port = addr  # Desempacota o endereço IP e a porta do peer

            try:
                # Recebe a chave pública do peer
                peer_public_key_bytes = self.receive_all(conn)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

                # Envia a chave pública do servidor para o peer
                conn.sendall(self.public_key_bytes)

                if peer_ip not in self.peers:
                    # Cria um novo objeto Peer e adiciona ao dicionário
                    peer = Peer(peer_ip, peer_port, conn, peer_public_key)
                    self.peers[peer_ip] = peer
                    print(f"New peer connected: {peer_ip}:{peer_port}")
                    # Inicia uma nova thread para receber mensagens deste peer
                    threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
                else:
                    # Atualiza a conexão e a chave pública do peer existente
                    print(f"Existing peer reconnected: {peer_ip}:{peer_port}")
                    self.peers[peer_ip].connection = conn
                    self.peers[peer_ip].public_key = peer_public_key
                    threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()

            except Exception as e:
                # Em caso de erro, imprime a mensagem e fecha a conexão
                print(f"Error establishing connection with {peer_ip}:{peer_port}: {e}")
                conn.close()

    # Função para conectar a um novo peer a partir da interface gráfica
    def connect_to_peer(self):
        peer_ip = self.peer_ip_entry.get()  # Obtém o IP inserido pelo utilizador
        peer_port = self.peer_port_entry.get()  # Obtém a porta inserida pelo utilizador

        if peer_ip and peer_port:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Cria um socket TCP
                sock.connect((peer_ip, int(peer_port)))  # Tenta conectar ao peer

                # Envia a chave pública do cliente para o peer
                sock.sendall(self.public_key_bytes)

                # Recebe a chave pública do peer
                peer_public_key_bytes = self.receive_all(sock)
                peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

                if peer_ip not in self.peers:
                    # Cria um novo objeto Peer e adiciona ao dicionário
                    peer = Peer(peer_ip, int(peer_port), sock, peer_public_key)
                    self.peers[peer_ip] = peer
                    # Inicia uma nova thread para receber mensagens deste peer
                    threading.Thread(target=self.receive_messages, args=(peer,), daemon=True).start()
                    messagebox.showinfo("Connection successful", f"Connected to {peer_ip}:{peer_port}")
                else:
                    # Atualiza a conexão e a chave pública do peer existente
                    self.peers[peer_ip].connection = sock
                    self.peers[peer_ip].public_key = peer_public_key
                    threading.Thread(target=self.receive_messages, args=(self.peers[peer_ip],), daemon=True).start()
                    messagebox.showinfo("Connection successful", f"Reusing connection with {peer_ip}:{peer_port}")

                self.setup_main_menu()  # Retorna ao menu principal

            except Exception as e:
                # Em caso de erro na conexão, mostra uma mensagem de erro
                messagebox.showerror("Connection error", f"Could not connect to {peer_ip}:{peer_port}\nError: {e}")

    # Função auxiliar para receber todos os dados de uma conexão
    def receive_all(self, conn):
        """
        Recebe todos os dados até que não haja mais dados disponíveis.
        Isto é útil para receber a chave pública completa.
        """
        data = b''  # Inicializa um buffer vazio
        while True:
            part = conn.recv(4096)  # Recebe dados em blocos de 4096 bytes
            data += part  # Adiciona ao buffer
            if len(part) < 4096:
                # Se o bloco recebido for menor que 4096, assume que não há mais dados
                break
        return data  # Retorna os dados recebidos

    # Função que lida com a receção de mensagens de um peer específico
    def receive_messages(self, peer):
        while True:
            try:
                encrypted_message = peer.connection.recv(4096)  # Recebe uma mensagem encriptada
                if encrypted_message:
                    # Desencripta a mensagem recebida usando a chave privada
                    message = self.decrypt_message(encrypted_message)
                    print(f"Message received from {peer.ip}:{peer.port}: {message}")
                    if peer.chat_window:
                        # Atualiza a janela de chat se estiver aberta
                        self.update_chat_window(peer, message, sender=False)
                    # Salva a mensagem num ficheiro de histórico
                    self.save_chat_to_file(peer, f"{peer.ip}:{peer.port}: {message}")
                else:
                    # Se não houver dados, assume que a conexão foi fechada
                    raise Exception("Connection closed")
            except Exception as e:
                # Em caso de erro, imprime a mensagem, fecha a conexão e remove o peer
                print(f"Connection to {peer.ip}:{peer.port} closed: {e}")
                peer.connection.close()
                del self.peers[peer.ip]
                break

    # Mostra a lista de peers conectados na interface gráfica
    def show_peer_list(self):
        if self.current_frame:
            self.current_frame.destroy()  # Remove o frame atual se existir

        self.current_frame = tk.Frame(self.root)  # Cria um novo frame
        self.current_frame.pack(pady=20)  # Adiciona padding vertical

        label = tk.Label(self.current_frame, text="Connected Peers")  # Título da lista de peers
        label.pack(pady=10)

        if not self.peers:
            # Se não houver peers conectados, mostra uma mensagem
            label = tk.Label(self.current_frame, text="No peers connected")
            label.pack(pady=10)
        else:
            # Cria uma Listbox para listar os peers
            listbox = tk.Listbox(self.current_frame)
            for idx, peer_ip in enumerate(self.peers):
                listbox.insert(idx, f"{peer_ip}:{self.peers[peer_ip].port}")  # Adiciona cada peer à lista
            listbox.pack(pady=10)

            # Função para abrir a janela de chat com o peer selecionado
            def open_chat():
                selected_idx = listbox.curselection()
                if selected_idx:
                    selected_peer_ip = listbox.get(selected_idx[0]).split(':')[0]  # Obtém o IP do peer selecionado
                    selected_peer = self.peers[selected_peer_ip]
                    self.open_chat_window(selected_peer)  # Abre a janela de chat

            # Botão para abrir o chat
            open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    # Abre uma janela de chat com o peer especificado
    def open_chat_window(self, peer):
        if peer.chat_window:
            peer.chat_window.lift()  # Traz a janela de chat para frente se já estiver aberta
            return

        # Cria uma nova janela de chat
        chat_window = tk.Toplevel(self.root)
        chat_window.title(f"Chat to {peer.ip}:{peer.port}")  # Título da janela de chat
        chat_window.geometry("500x500")  # Define o tamanho da janela

        # Área de texto para exibir as mensagens
        chat_text = tk.Text(chat_window, height=25, width=60, state=tk.DISABLED)
        chat_text.pack(pady=10)

        # Carrega o histórico de conversas de um ficheiro
        self.load_chat_from_file(peer, chat_text)

        message_var = tk.StringVar()  # Variável para armazenar a mensagem a enviar
        # Campo de entrada para escrever a mensagem
        message_entry = tk.Entry(chat_window, textvariable=message_var, width=50)
        message_entry.pack(pady=5, padx=10, fill=tk.X)

        # Botão para enviar a mensagem
        send_button = tk.Button(chat_window, text="Send", command=lambda: self.send_message(peer, message_var, chat_text))
        send_button.pack(pady=5)

        # Permite enviar a mensagem pressionando a tecla Enter
        message_entry.bind('<Return>', lambda event: self.send_message(peer, message_var, chat_text))

        peer.chat_window = chat_window  # Associa a janela de chat ao peer

        # Função para lidar com o fechamento da janela de chat
        def on_close():
            peer.chat_window = None  # Remove a referência à janela de chat
            chat_window.destroy()  # Fecha a janela

        chat_window.protocol("WM_DELETE_WINDOW", on_close)  # Liga a função de fechamento

    # Envia uma mensagem para o peer especificado
    def send_message(self, peer, message_var, text_area):
        message = message_var.get()  # Obtém a mensagem do campo de entrada
        if message:
            message_var.set("")  # Limpa o campo de entrada

            try:
                # Encripta a mensagem usando a chave pública do peer
                encrypted_message = self.encrypt_message(message, peer.public_key)
                peer.connection.sendall(encrypted_message)  # Envia a mensagem encriptada
                self.update_chat_window(peer, message, sender=True)  # Atualiza a janela de chat
                self.save_chat_to_file(peer, f"You: {message}")  # Salva a mensagem no histórico
            except Exception as e:
                # Em caso de erro, mostra uma mensagem de erro
                messagebox.showerror("Error", f"Could not send message: {e}")

    # Atualiza a janela de chat com a nova mensagem
    def update_chat_window(self, peer, message, sender=False):
        if peer.chat_window:
            text_area = peer.chat_window.children.get('!text')  # Obtém a área de texto
            if text_area:
                text_area.config(state=tk.NORMAL)  # Permite editar o texto
                if sender:
                    text_area.insert(tk.END, f"You: {message}\n")  # Adiciona a mensagem enviada
                else:
                    text_area.insert(tk.END, f"{peer.ip}:{peer.port}: {message}\n")  # Adiciona a mensagem recebida
                text_area.config(state=tk.DISABLED)  # Torna a área de texto somente leitura
                text_area.see(tk.END)  # Rola para a última linha

    # Salva a mensagem no histórico de conversas num ficheiro
    def save_chat_to_file(self, peer, message):
        # Define o nome do ficheiro com base no IP e porta do peer
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(message + '\n')  # Adiciona a mensagem ao ficheiro

    # Carrega o histórico de conversas de um ficheiro e o exibe na área de texto
    def load_chat_from_file(self, peer, text_area):
        # Define o nome do ficheiro com base no IP e porta do peer
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                chat_history = f.read()  # Lê o conteúdo do ficheiro
                text_area.config(state=tk.NORMAL)  # Permite editar o texto
                text_area.insert(tk.END, chat_history)  # Insere o histórico na área de texto
                text_area.config(state=tk.DISABLED)  # Torna a área de texto somente leitura

    # Encripta a mensagem usando a chave pública do peer
    def encrypt_message(self, message, peer_public_key):
        # Utiliza OAEP com SHA256 para encriptação
        encrypted = peer_public_key.encrypt(
            message.encode('utf-8'),  # Converte a mensagem para bytes
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Função de máscara de mensagem
                algorithm=hashes.SHA256(),  # Algoritmo de hash
                label=None
            )
        )
        return encrypted  # Retorna a mensagem encriptada

    # Desencripta a mensagem recebida usando a chave privada
    def decrypt_message(self, encrypted_message):
        # Utiliza OAEP com SHA256 para desencriptação
        decrypted = self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Função de máscara de mensagem
                algorithm=hashes.SHA256(),  # Algoritmo de hash
                label=None
            )
        )
        return decrypted.decode('utf-8')  # Converte os bytes de volta para string

# Função principal para iniciar o cliente-servidor
def start_peer():
    root = tk.Tk()
    root.withdraw()  # Oculta a janela principal para perguntar a porta do servidor

    # Pergunta a porta local do cliente através de um diálogo simples
    local_port = simpledialog.askinteger("Port", "Enter the local port:")
    root.destroy()  # Fecha a janela oculta

    if local_port:
        try:
            host = socket.gethostbyname(socket.gethostname())  # Obtém o IP local
        except Exception:
            host = '127.0.0.1'  # Fallback para localhost se não conseguir obter o IP
        app = P2PChatApp(host, local_port)  # Cria uma instância da aplicação
        app.root.mainloop()  # Inicia o loop principal da interface gráfica
    else:
        # Mostra uma mensagem de erro se a porta for inválida
        messagebox.showerror("Error", "Invalid port! The application will be...")

# Verifica se o script está a ser executado diretamente
if __name__ == "__main__":
    start_peer()
