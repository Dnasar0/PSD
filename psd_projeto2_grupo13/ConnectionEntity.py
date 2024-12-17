# ConnectionEntity.py
# Class representing a connected Peer or Group

class ConnectionEntity:
    def __init__(self, ip, port, connection, public_key, aes_key, is_group=False, group_name=None):
        self.ip = ip  # IP address of the peer
        self.port = port  # Port number of the peer
        self.connection = connection  # Socket connection object
        self.public_key = public_key  # ECDH public key of the peer/group
        self.aes_key = aes_key  # AES key for secure communication
        self.chat_window = None  # Chat window associated with the peer/group
        self.chat_text = None  # Text widget in the chat window
        self.is_group = is_group  # Flag to indicate if it's a group
        self.group_name = group_name  # Group name, if it's a group
        self.messages = []  # List to store messages for searching
        self.group_key_shares = []  # List to store shares of the group key for Shamir's Secret Sharing
        self.group_key = None  # Reconstructed group key
