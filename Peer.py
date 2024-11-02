# Class representing a connected Peer
class Peer:
    def __init__(self, ip, port, connection, certificate, aes_key, dh_private_key=None, dh_public_key=None):
        self.ip = ip
        self.port = port
        self.connection = connection
        self.certificate = certificate  # x509 certificate of the peer
        self.aes_key = aes_key  # AES key for secure communication
        self.dh_private_key = dh_private_key  # DH private key
        self.dh_public_key = dh_public_key    # DH public key
        self.chat_window = None  # Chat window associated with the peer