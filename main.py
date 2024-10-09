from peer import Peer
from p2pchatapp import P2PChatApp

def main():
    # Defina o host como 'localhost'
    host = 'localhost'  # Ou use socket.gethostbyname(socket.gethostname()) para o IP local

    # Crie uma instância da classe Peer
    peer = Peer(host)

    # Inicie a escuta por conexões
    peer.start()

    # Exibir a porta escolhida automaticamente
    print(f"Você está ouvindo na porta: {peer.port}")

    # Inicie a aplicação gráfica
    app = P2PChatApp(peer)
    app.mainloop()

if __name__ == "__main__":
    main()
