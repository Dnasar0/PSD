from peer import Peer
from p2pchatapp import P2PChatApp

def get_user_input():
    # Solicita o IP e a porta ao usuário
    host = input("Digite o endereço IP (padrão: localhost): ")
    if not host:  # Set default value if input is empty
        host = "localhost"
        
    try:
        port = int(input("Digite a porta (padrão: 5000): "))
    except ValueError:
        print("Porta inválida. Usando a porta padrão: 5000.")
        port = 5000  # Default port

    return host, port

if __name__ == "__main__":
    # Obtém o host e a porta do usuário
    host, port = get_user_input()

    # Cria uma instância da classe Peer com o host e porta especificados
    peer = Peer(host, port)
    peer.start()  # Inicie a escuta em uma thread separada

    # Inicia a aplicação principal
    app = P2PChatApp(peer)
    app.mainloop()
