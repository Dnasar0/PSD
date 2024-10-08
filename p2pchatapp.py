import os
import tkinter as tk
from tkinter import messagebox

from chatwindow import ChatWindow

class P2PChatApp(tk.Tk):
    def __init__(self, peer):
        super().__init__()
        self.peer = peer
        self.title("P2P Chat App")
        self.geometry("400x400")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.main_frame = tk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.ip_label = tk.Label(self.main_frame, text=f"Your IP: {self.peer.host}\nYour Port: {self.peer.port}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        self.create_menu()

    def create_menu(self):
        """Create the initial menu with options."""
        self.clear_frame()

        self.ip_label = tk.Label(self.main_frame, text=f"Your IP: {self.peer.host}\nYour Port: {self.peer.port}", font=("Arial", 12))
        self.ip_label.pack(pady=10)

        self.label = tk.Label(self.main_frame, text="Welcome to P2P Chat", font=("Arial", 16))
        self.label.pack(pady=20)

        self.create_connection_button = tk.Button(self.main_frame, text="Create New Connection", command=self.open_new_connection_frame)
        self.create_connection_button.pack(pady=10)

        self.view_clients_button = tk.Button(self.main_frame, text="View Connected Clients", command=self.open_view_clients_frame)
        self.view_clients_button.pack(pady=10)

    def clear_frame(self):
        """Clear the current frame."""
        for widget in self.main_frame.winfo_children():
            widget.destroy()

    def open_new_connection_frame(self):
        """Open the frame for new connections."""
        self.clear_frame()

        tk.Label(self.main_frame, text="New Connection", font=("Arial", 16)).pack(pady=10)

        tk.Label(self.main_frame, text="Host:").pack()
        self.entry_host = tk.Entry(self.main_frame)
        self.entry_host.pack(fill=tk.X, padx=10)

        tk.Label(self.main_frame, text="Port:").pack()
        self.entry_port = tk.Entry(self.main_frame)
        self.entry_port.pack(fill=tk.X, padx=10)

        tk.Label(self.main_frame, text="Client Name:").pack()
        self.entry_name = tk.Entry(self.main_frame)
        self.entry_name.pack(fill=tk.X, padx=10)

        self.connect_button = tk.Button(self.main_frame, text="Connect", command=self.connect)
        self.connect_button.pack(pady=20)

        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack()

    def connect(self):
        host = self.entry_host.get()
        port = int(self.entry_port.get())
        client_name = self.entry_name.get()

        self.peer.connect(host, port, client_name)
        messagebox.showinfo("Connection", f"Connected to {client_name}!")

    def open_view_clients_frame(self):
        """Open the frame to view connected clients."""
        self.clear_frame()
        tk.Label(self.main_frame, text="Connected Clients", font=("Arial", 16)).pack(pady=10)

        self.client_listbox = tk.Listbox(self.main_frame)
        self.client_listbox.pack(fill=tk.BOTH, expand=True, padx=10)

        #self.load_clients()
        self.load_contact_list()

        self.start_chat_button = tk.Button(self.main_frame, text="Start Chat", command=self.start_chat)
        self.start_chat_button.pack(pady=10)
        
        self.edit_name_button = tk.Button(self.main_frame, text="Edit Contact Name", command=self.edit_client_name)
        self.edit_name_button.pack(pady=10)

        self.back_button = tk.Button(self.main_frame, text="Back", command=self.create_menu)
        self.back_button.pack()

    def edit_client_name(self):
        """Edit the name of the selected client."""
        selected_client = self.client_listbox.curselection()
        if selected_client:
            client_name = self.client_listbox.get(selected_client)

            edit_window = tk.Toplevel(self)
            edit_window.title(f"Edit Name of {client_name}")
            edit_window.geometry("300x150")

            tk.Label(edit_window, text="Enter new name:").pack(pady=10)
            new_name_entry = tk.Entry(edit_window)
            new_name_entry.pack(pady=5, padx=20)

            def save_new_name():
                new_name = new_name_entry.get()
                if new_name:
                    # Obtenha o IP e Porta do cliente selecionado
                    client_info = self.peer.connections[client_name]
                    host, port = client_info['address']

                    # Caminho para o ficheiro contacts.txt
                    contacts_list_path = os.path.join(self.peer.folder_path, self.peer.contactsListFile)
                    contactsListPath = self.peer.folder_path + "/" + self.peer.contactsListFile
                    if os.path.exists(contactsListPath):
                        with open(contactsListPath, "r") as file:
                            lines = file.readlines()

                        # Procurar e modificar a linha correspondente ao contato
                        updated_lines = []
                        for line in lines:
                            print(line)
                            contact_ip_port, contact_name = line.strip().split('-')
                            print(contact_ip_port)
                            print(contact_name)
                            if contact_ip_port == f"{host}_{port}":
                                # Substituir pelo novo nome
                                updated_lines.append(f"{contact_ip_port}-{new_name}\n")
                            else:
                                updated_lines.append(line)

                        # Reescrever o ficheiro com o nome atualizado
                        with open(contactsListPath, 'w') as file:
                            file.writelines(updated_lines)

                        print(self.peer.connections)
                        # Atualizar o nome na lista de conexões (dicionário interno)
                        connection_data  = self.peer.connections.pop(client_name)
                        self.peer.connections[new_name] = connection_data
                        print(self.peer.connections)
                        # Atualizar a listbox de clientes
                        self.load_clients()

                        messagebox.showinfo("Success", f"Contact name updated to {new_name}")
                        edit_window.destroy()
                    else:
                        messagebox.showerror("Error", "Contacts file not found.")
                else:
                    messagebox.showwarning("Invalid Input", "Please enter a valid name.")

            tk.Button(edit_window, text="Save", command=save_new_name).pack(pady=10)

        else:
            messagebox.showwarning("Invalid Selection", "Please select a client to edit the name.")


    def load_contact_list(self):
        """Carregar a lista de contactos do ficheiro contacts.txt e exibir na listbox."""
        contacts_list_path = os.path.join(self.peer.folder_path, self.peer.contactsListFile)

        if os.path.exists(contacts_list_path):
            with open(contacts_list_path, 'r') as file:
                contacts = file.readlines()

            # Adicionar os contactos à listbox
            for contact in contacts:
                contact = contact.strip().split('-')[-1]  # Remover quebras de linha
                self.client_listbox.insert(tk.END, contact)
        else:
            messagebox.showinfo("Info", "No contacts found.")


    def load_clients(self):
        """Load the list of connected clients."""
        self.client_listbox.delete(0, tk.END)
        for (name, host, port) in self.peer.get_connected_clients():
            self.client_listbox.insert(tk.END, name)

    def start_chat(self):
        selected_client = self.client_listbox.curselection()
        if selected_client:
            client_name = self.client_listbox.get(selected_client)
            
            # Carregar histórico da conversa do cliente
            client_info = self.peer.connections.get(client_name)
            if client_info:
                host, port = client_info['address']
                file_path = os.path.join(self.peer.folder_path, f"{host}_{port}.txt")

                self.chat_window = ChatWindow(self.peer, client_name, file_path)
            else:
                host_port= None
                #Abrir lista de contactos
                contacts_list_path = os.path.join(self.peer.folder_path, self.peer.contactsListFile)
                if os.path.exists(contacts_list_path):
                    with open(contacts_list_path, 'r') as file:
                        contacts = file.readlines()

                    # Encontrar ip:port correspondente a client_name
                    for contact in contacts:
                        if contact.strip().split('-')[-1] == client_name: #Verifica se o nome do contato corresponde ao selecionado
                            host_port = contact.strip().split('-')[0] #Obtemm o ip:port do contato
                            host, port = host_port.split('_')
                            self.peer.connect(host, port, client_name) #Conecta-se ao contato
                            break
                client_info = self.peer.connections.get(client_name)
                host, port = client_info['address']
                file_path = os.path.join(self.peer.folder_path, f"{host}_{port}.txt")
                self.chat_window = ChatWindow(self.peer, client_name, file_path)
            
            #self.chat_window = ChatWindow(self.peer, client_name, None)
        else:
            messagebox.showwarning("Invalid Selection", "Please select a client to start the chat.")

    def on_close(self):
        """Close the application and shut down the server."""
        self.peer.socket.close()
        self.destroy()