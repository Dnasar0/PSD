# TkApp.py

import os
import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import base64

import p2pchat_phase2 as P2PChat
from p2pchat_phase2 import sanitize_for_firebase_path
from firebase_admin import db

class TkApp:
    def __init__(self, p2p, host, port):
        self.root = tk.Tk()
        self.root.title(f"P2P Chat Application: {host}:{port}")
        self.root.geometry("500x500")
        self.root.minsize(500, 500)
        self.host = host
        self.port = port
        self.p2p = p2p
        self.current_frame = None
        self.setup_main_menu()
        
    def get_root(self):
        return self.root
    
    def setup_main_menu(self):
        """
        Configura o menu principal da interface gráfica com opções para conectar, visualizar peers, pesquisar mensagens e ver recomendações.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        # Exibe o IP e porta do usuário
        self.info_label = tk.Label(self.current_frame, text=f"Seu IP: {self.host}\nSua Porta: {self.port}")
        self.info_label.pack(pady=10)

        # Botão para conectar a um novo peer ou grupo
        self.connect_button = tk.Button(self.current_frame, text="Conectar", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        # Botão para visualizar a lista de peers e grupos conectados
        self.list_button = tk.Button(self.current_frame, text="Lista de Peers/Grupos", command=self.show_peer_list)
        self.list_button.pack(pady=10)

        # Botão para pesquisar mensagens
        self.search_button = tk.Button(self.current_frame, text="Pesquisar Mensagens", command=self.search_messages)
        self.search_button.pack(pady=10)

        # Botão para adicionar Tópicos de Interesse
        self.topics_button = tk.Button(self.current_frame, text="Tópicos de Interesse", command=self.show_topics_window)
        self.topics_button.pack(pady=10)

        # Botão para visualizar recomendações personalizadas
        self.recommendations_button = tk.Button(self.current_frame, text="Ver Recomendações", command=self.show_recommendations)
        self.recommendations_button.pack(pady=10)

    def show_topics_window(self):
        """
        Exibe a seleção de tópicos na mesma janela.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Selecione Tópicos de Interesse").pack(pady=10)

        # Lista de tópicos
        topics = ["Carros", "Música", "Futebol", "Basquete", "Cibersegurança", "IA-Inteligência Artificial", "IoT-Internet das Coisas"]

        # Dicionário para armazenar as variáveis dos tópicos
        self.topic_vars = {}
        for topic in topics:
            var = tk.IntVar()
            self.topic_vars[topic] = var
            cb = tk.Checkbutton(self.current_frame, text=topic, variable=var)
            cb.pack(anchor=tk.W)

        # Carrega os tópicos existentes do usuário no Firebase
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_data = user_ref.get()
        if user_data and 'topics' in user_data:
            selected_topics = user_data['topics']
            for topic in selected_topics:
                if topic in self.topic_vars:
                    self.topic_vars[topic].set(1)

        # Botão para salvar
        save_button = tk.Button(self.current_frame, text="Salvar", command=self.save_topics)
        save_button.pack(pady=10)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def save_topics(self):
        """
        Salva os tópicos selecionados pelo usuário no Firebase.
        """
        selected_topics = [topic for topic, var in self.topic_vars.items() if var.get() == 1]
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_ref.update({'topics': selected_topics})
        messagebox.showinfo("Tópicos Salvos", "Seus tópicos de interesse foram salvos.")
        # Retorna ao menu principal
        self.setup_main_menu()

    def show_connection_inputs(self):
        """
        Exibe os campos de entrada para conectar a um novo peer ou grupo.
        """
        self.clear_frame()

        # Variável para armazenar o tipo de conexão selecionado (peer ou grupo)
        connection_type_var = tk.StringVar(value="peer")
        tk.Label(self.current_frame, text="Tipo de Conexão:").pack(pady=5)
        # Botões de opção para selecionar o tipo de conexão
        tk.Radiobutton(self.current_frame, text="Peer", variable=connection_type_var, value="peer", command=self.update_connection_inputs).pack()
        tk.Radiobutton(self.current_frame, text="Grupo", variable=connection_type_var, value="group", command=self.update_connection_inputs).pack()

        self.connection_type_var = connection_type_var

        # Cria frames para entradas de peer e de grupo
        self.peer_inputs_frame = tk.Frame(self.current_frame)
        self.group_inputs_frame = tk.Frame(self.current_frame)

        # Entradas para peer
        tk.Label(self.peer_inputs_frame, text="IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.peer_inputs_frame, text="Porta:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_port_entry.pack(pady=5)

        # Inicialmente mostra entradas para peer
        self.peer_inputs_frame.pack()

        # Botão para iniciar conexão
        self.connect_peer_button = tk.Button(
            self.current_frame,
            text="Conectar",
            command=self.connect_to_selected_entity
        )
        self.connect_peer_button.pack(pady=10)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def update_connection_inputs(self):
        """
        Atualiza os campos de entrada mostrados com base no tipo de conexão selecionado (peer ou grupo).
        """
        connection_type = self.connection_type_var.get()
        if connection_type == 'peer':
            # Mostra entradas para peer e esconde entradas para grupo
            self.group_inputs_frame.pack_forget()
            self.peer_inputs_frame.pack()
        elif connection_type == 'group':
            # Mostra entradas para grupo e esconde entradas para peer
            self.peer_inputs_frame.pack_forget()
            # Em vez de entrada para nome do grupo, mostra lista de grupos
            self.show_group_selection()

    def show_group_selection(self):
        """
        Exibe uma lista de grupos nos tópicos de interesse do usuário.
        """
        # Limpa group_inputs_frame
        for widget in self.group_inputs_frame.winfo_children():
            widget.destroy()

        # Obtém os tópicos do usuário
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_data = user_ref.get()
        user_topics = user_data.get('topics', []) if user_data else []

        if not user_topics:
            messagebox.showerror("Erro", "Você não selecionou nenhum tópico de interesse. Por favor, selecione tópicos antes de conectar a grupos.")
            return

        # Obtém a lista de grupos do Firebase
        groups_ref = db.reference("groups")
        groups_data = groups_ref.get()
        available_groups = []
        if groups_data:
            for group_name, group_info in groups_data.items():
                group_topic = group_info.get('topic')
                if group_topic in user_topics:
                    available_groups.append(group_name)

        label = tk.Label(self.group_inputs_frame, text="Selecione um Grupo:")
        label.pack()
        self.group_listbox = tk.Listbox(self.group_inputs_frame)
        if available_groups:
            for idx, group_name in enumerate(available_groups):
                self.group_listbox.insert(idx, group_name)
        else:
            self.group_listbox.insert(0, "Nenhum grupo disponível em seus tópicos de interesse.")
            self.group_listbox.config(state=tk.DISABLED)
        self.group_listbox.pack()

        # Botão para criar novo grupo
        create_group_button = tk.Button(self.group_inputs_frame, text="Criar Novo Grupo", command=self.create_new_group)
        create_group_button.pack(pady=5)

        self.group_inputs_frame.pack()

    def create_new_group(self):
        """
        Permite ao usuário criar um novo grupo em seus tópicos de interesse.
        """
        # Solicita o nome do grupo
        group_name = simpledialog.askstring("Novo Grupo", "Insira o nome do novo grupo:")
        if not group_name:
            return

        # Obtém os tópicos do usuário
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        user_ref = db.reference(f"users/{user_id}")
        user_data = user_ref.get()
        user_topics = user_data.get('topics', []) if user_data else []

        # Solicita ao usuário que selecione um tópico para o novo grupo entre seus tópicos de interesse
        if not user_topics:
            messagebox.showerror("Erro", "Você não selecionou nenhum tópico de interesse.")
            return

        topic = simpledialog.askstring("Tópico do Grupo", "Selecione um tópico para o novo grupo:\n" + "\n".join(user_topics))
        if not topic or topic not in user_topics:
            messagebox.showerror("Erro", "Tópico inválido selecionado para o grupo.")
            return

        # Salva o tópico do grupo no Firebase
        group_id = sanitize_for_firebase_path(group_name)
        group_ref = db.reference(f"groups/{group_id}")
        group_data = group_ref.get()
        if group_data:
            messagebox.showerror("Erro", f"O grupo '{group_name}' já existe.")
            return

        group_ref.set({'topic': topic})
        messagebox.showinfo("Grupo Criado", f"Grupo '{group_name}' foi criado.")

        # Atualiza a lista de grupos
        self.show_group_selection()

    def connect_to_selected_entity(self):
        """
        Conecta à entidade selecionada (peer ou grupo) com base nas entradas.
        """
        connection_type = self.connection_type_var.get()
        if connection_type == 'peer':
            # Obtém IP e porta dos campos de entrada
            peer_ip = self.peer_ip_entry.get()
            peer_port = self.peer_port_entry.get()

            # Validação de entrada para IP e porta
            if not self.p2p.validate_ip(peer_ip) or not peer_port.isdigit():
                messagebox.showerror("Erro", "IP ou porta inválidos!")
                return

            peer_port = int(peer_port)

            if (peer_ip, peer_port) in self.p2p.peers:
                messagebox.showinfo("Info", f"Já está conectado a {peer_ip}:{peer_port}")
                return

            # Inicia uma thread para conectar ao peer e atualizar a interface
            threading.Thread(target=self.p2p.connect_to_peer_ui, args=(peer_ip, peer_port), daemon=True).start()

        elif connection_type == 'group':
            # Obtém o grupo selecionado da listbox
            selected_idx = self.group_listbox.curselection()
            if selected_idx:
                group_name = self.group_listbox.get(selected_idx[0])
                self.p2p.connect_to_group(group_name)
            else:
                messagebox.showerror("Erro", "Nenhum grupo selecionado.")

    def clear_frame(self):
        """
        Limpa o frame atual para carregar novos widgets.
        """
        for widget in self.current_frame.winfo_children():
            widget.destroy()
            
    def show_peer_list(self):
        """
        Exibe a lista de peers e grupos conectados.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Peers e Grupos Conectados")
        label.pack(pady=10)

        if not self.p2p.peers:
            label = tk.Label(self.current_frame, text="Nenhum peer ou grupo conectado")
            label.pack(pady=10)
        else:
            # Listbox para exibir peers e grupos
            listbox = tk.Listbox(self.current_frame)
            for idx, key in enumerate(self.p2p.peers):
                entity = self.p2p.peers[key]
                if entity.is_group:
                    listbox.insert(idx, f"Grupo - {entity.group_name}")
                else:
                    listbox.insert(idx, f"Peer - {entity.ip}:{entity.port}")
            listbox.pack(pady=10)

            def open_chat():
                # Abre a janela de chat com o peer ou grupo selecionado
                selected_idx = listbox.curselection()
                if selected_idx:
                    selected_item = listbox.get(selected_idx[0])
                    if selected_item.startswith('Grupo - '):
                        group_name = selected_item[len('Grupo - '):]
                        selected_entity = self.p2p.peers[group_name]
                    elif selected_item.startswith('Peer - '):
                        addr = selected_item[len('Peer - '):]
                        selected_ip, selected_port = addr.split(':')
                        selected_port = int(selected_port)
                        selected_entity = self.p2p.peers.get((selected_ip, selected_port))
                        if not selected_entity:
                            messagebox.showerror("Erro", f"Peer {selected_ip}:{selected_port} não está conectado.")
                            return
                    self.open_chat_window(selected_entity)

            # Botão para abrir chat com a entidade selecionada
            open_chat_button = tk.Button(self.current_frame, text="Abrir Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, entity):
        """
        Abre uma janela de chat para comunicação com o peer ou grupo.
        """
        if entity.chat_window:
            # Verifica se a janela já está aberta
            try:
                entity.chat_window.winfo_exists()
                entity.chat_window.lift()
                return
            except tk.TclError:
                # A janela não existe mais; reseta referências
                entity.chat_window = None
                entity.chat_text = None

        # Cria uma nova janela para o chat
        chat_window = tk.Toplevel(self.root)
        if entity.is_group:
            title = f"Chat com Grupo '{entity.group_name}'"
        else:
            title = f"Chat com Peer {entity.ip}:{entity.port}"
        chat_window.title(title)
        chat_window.geometry("500x500")

        # Frame principal para a janela de chat
        main_frame = tk.Frame(chat_window)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Área de texto para histórico do chat
        chat_text = tk.Text(main_frame, height=20, width=60)
        chat_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        chat_text.config(state=tk.DISABLED)

        # Carrega histórico do chat dos bancos de dados em nuvem
        threading.Thread(target=self.load_chat_history, args=(entity, chat_text), daemon=True).start()

        # Frame para entrada de mensagem e botões
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Botão para fechar a janela de chat
        back_button = tk.Button(bottom_frame, text="Voltar", command=lambda: self.close_chat_window(entity))
        back_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Campo de entrada de mensagem
        message_var = tk.StringVar()
        message_entry = tk.Entry(bottom_frame, textvariable=message_var)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0), pady=5)

        # Botão para enviar mensagens
        send_button = tk.Button(bottom_frame, text="Enviar", command=lambda: self.p2p.send_message(entity, message_var))
        send_button.pack(side=tk.RIGHT, padx=(0, 5), pady=5)

        # Vincula a tecla Enter para enviar mensagem
        message_entry.bind('<Return>', lambda event: self.p2p.send_message(entity, message_var))

        # Armazena referências para a janela de chat e área de texto
        entity.chat_window = chat_window
        entity.chat_text = chat_text

        def on_close():
            # Manipula o evento de fechar a janela de chat
            self.close_chat_window(entity)

        chat_window.protocol("WM_DELETE_WINDOW", on_close)
        
    def close_chat_window(self, entity):
        """
        Fecha a janela de chat e limpa as referências.
        """
        if entity.chat_window:
            entity.chat_window.destroy()
            entity.chat_window = None
            entity.chat_text = None    

    def update_chat_window(self, entity, message):
        """
        Atualiza a janela de chat com novas mensagens.
        """
        if entity.chat_window:
            text_area = entity.chat_text
            if text_area:
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, message + '\n')
                text_area.config(state=tk.DISABLED)
                text_area.see(tk.END)
                
    def load_chat_history(self, entity, text_area):
        """
        Carrega o histórico de conversa dos bancos de dados em nuvem.
        """
        messages = self.p2p.load_messages_from_cloud(entity)
        for msg in messages:
            sender = msg.get('sender', '')
            message = msg.get('message', '')
            if sender:
                display_message = f"{sender}: {message}"
            else:
                display_message = message
            text_area.config(state=tk.NORMAL)
            text_area.insert(tk.END, display_message + '\n')
            text_area.config(state=tk.DISABLED)
        text_area.see(tk.END)

    def show_recommendations(self):
        """
        Exibe recomendações personalizadas para o usuário.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Suas Recomendações").pack(pady=10)

        # Área de texto para exibir recomendações
        recommendations_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        recommendations_text.pack(pady=10)

        try:
            # Recupera recomendações da P2PChatApp
            recommended_topics, recommended_groups = self.p2p.get_recommendations()

            recommendations_text.config(state=tk.NORMAL)
            if recommended_topics:
                recommendations_text.insert(tk.END, "Com base em suas mensagens, você pode estar interessado nestes tópicos:\n")
                for topic, count in recommended_topics:
                    recommendations_text.insert(tk.END, f"- {topic} ({count} menções)\n")
            else:
                recommendations_text.insert(tk.END, "Nenhuma recomendação de tópico no momento.\n")

            if recommended_groups:
                recommendations_text.insert(tk.END, "\nVocê pode estar interessado em participar destes grupos:\n")
                for group_name, group_topic in recommended_groups:
                    recommendations_text.insert(tk.END, f"- {group_name} (Tópico: {group_topic})\n")
            else:
                recommendations_text.insert(tk.END, "Nenhuma recomendação de grupo no momento.")
            recommendations_text.config(state=tk.DISABLED)
        except Exception as e:
            # Trata exceções, como erros do Firebase
            messagebox.showerror("Erro", f"Ocorreu um erro ao buscar recomendações:\n{e}")
            self.setup_main_menu()
            return

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)  
        
    def search_messages(self):
        """
        Permite aos usuários pesquisar conversas usando palavras-chave sem comprometer a segurança das mensagens.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Pesquisar Mensagens").pack(pady=10)

        # Campo de entrada para palavras-chave
        keyword_var = tk.StringVar()
        keyword_entry = tk.Entry(self.current_frame, textvariable=keyword_var, width=30)
        keyword_entry.pack(pady=5)
        keyword_entry.focus_set()  # Garante que o widget de entrada aceite entrada

        # Área de texto para exibir resultados de pesquisa
        result_text = tk.Text(self.current_frame, height=15, width=60)
        result_text.pack(pady=10)
        result_text.config(state=tk.DISABLED)

        def perform_search():
            # Executa a pesquisa com base nas palavras-chave de entrada
            keywords = keyword_var.get().strip()
            if keywords:
                keyword_list = keywords.split()
                result_text.config(state=tk.NORMAL)
                result_text.delete('1.0', tk.END)
                results = self.p2p.perform_privacy_preserving_search(keyword_list)
                if results:
                    for res in results:
                        result_text.insert(tk.END, res + '\n')
                else:
                    result_text.insert(tk.END, "Nenhuma mensagem correspondente encontrada.")
                result_text.config(state=tk.DISABLED)

        # Botão para iniciar pesquisa
        search_button = tk.Button(self.current_frame, text="Pesquisar", command=perform_search)
        search_button.pack(pady=5)

        # Botão para voltar ao menu principal
        back_button = tk.Button(self.current_frame, text="Voltar", command=self.setup_main_menu)
        back_button.pack(pady=10)
