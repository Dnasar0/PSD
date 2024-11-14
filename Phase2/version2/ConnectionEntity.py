# ConnectionEntity.py

# Classe que representa um Peer ou Grupo conectado
class ConnectionEntity:
    def __init__(self, ip, port, connection, public_key, aes_key, is_group=False, group_name=None):
        self.ip = ip  # Endereço IP do peer
        self.port = port  # Número da porta do peer
        self.connection = connection  # Objeto de conexão socket
        self.public_key = public_key  # Chave pública ECDH do peer/grupo
        self.aes_key = aes_key  # Chave AES para comunicação segura
        self.chat_window = None  # Janela de chat associada ao peer/grupo
        self.chat_text = None  # Widget de texto na janela de chat
        self.is_group = is_group  # Flag para indicar se é um grupo
        self.group_name = group_name  # Nome do grupo, se for um grupo
        self.messages = []  # Lista para armazenar mensagens para pesquisa
