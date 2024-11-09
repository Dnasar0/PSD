import os
import tkinter as tk
from tkinter import messagebox
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
        Sets up the main menu of the GUI with options to connect, view peers, search messages, and view recommendations.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        # Display the user's IP and port
        self.info_label = tk.Label(self.current_frame, text=f"Your IP: {self.host}\nYour Port: {self.port}")
        self.info_label.pack(pady=10)

        # Button to connect to a new peer or group
        self.connect_button = tk.Button(self.current_frame, text="Connect", command=self.show_connection_inputs)
        self.connect_button.pack(pady=10)

        # Button to view the list of connected peers and groups
        self.list_button = tk.Button(self.current_frame, text="Peers/Groups List", command=self.show_peer_list)
        self.list_button.pack(pady=10)

        # Button to search messages
        self.search_button = tk.Button(self.current_frame, text="Search Messages", command=self.search_messages)
        self.search_button.pack(pady=10)

        # Button to view personalized recommendations
        self.recommendations_button = tk.Button(self.current_frame, text="View Recommendations", command=self.show_recommendations)
        self.recommendations_button.pack(pady=10)

    def show_connection_inputs(self):
        """
        Displays the input fields to connect to a new peer or group.
        """
        self.clear_frame()

        # Variable to store the selected connection type (peer or group)
        connection_type_var = tk.StringVar(value="peer")
        tk.Label(self.current_frame, text="Connection Type:").pack(pady=5)
        # Radio buttons to select connection type
        tk.Radiobutton(self.current_frame, text="Peer", variable=connection_type_var, value="peer", command=self.update_connection_inputs).pack()
        tk.Radiobutton(self.current_frame, text="Group", variable=connection_type_var, value="group", command=self.update_connection_inputs).pack()

        self.connection_type_var = connection_type_var

        # Create frames for peer inputs and group inputs
        self.peer_inputs_frame = tk.Frame(self.current_frame)
        self.group_inputs_frame = tk.Frame(self.current_frame)

        # Peer inputs
        tk.Label(self.peer_inputs_frame, text="IP:").pack(pady=5)
        self.peer_ip_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_ip_entry.pack(pady=5)

        tk.Label(self.peer_inputs_frame, text="Port:").pack(pady=5)
        self.peer_port_entry = tk.Entry(self.peer_inputs_frame)
        self.peer_port_entry.pack(pady=5)

        # Group inputs
        tk.Label(self.group_inputs_frame, text="Group Name:").pack(pady=5)
        self.group_name_entry = tk.Entry(self.group_inputs_frame)
        self.group_name_entry.pack(pady=5)

        # Initially show peer inputs
        self.peer_inputs_frame.pack()

        # Button to initiate connection
        self.connect_peer_button = tk.Button(
            self.current_frame,
            text="Connect",
            command=lambda: self.p2p.connect_to_entity(connection_type_var.get())
        )
        self.connect_peer_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)
        
    def update_connection_inputs(self):
        """
        Updates the input fields shown based on the connection type selected (peer or group).
        """
        connection_type = self.connection_type_var.get()
        if connection_type == 'peer':
            # Show peer inputs and hide group inputs
            self.group_inputs_frame.pack_forget()
            self.peer_inputs_frame.pack()
        elif connection_type == 'group':
            # Show group inputs and hide peer inputs
            self.peer_inputs_frame.pack_forget()
            self.group_inputs_frame.pack()        

    def clear_frame(self):
        """
        Clears the current frame to load new widgets.
        """
        for widget in self.current_frame.winfo_children():
            widget.destroy()
            
    def show_peer_list(self):
        """
        Displays the list of connected peers and groups.
        """
        if self.current_frame:
            self.current_frame.destroy()

        self.current_frame = tk.Frame(self.root)
        self.current_frame.pack(pady=20)

        label = tk.Label(self.current_frame, text="Connected Peers and Groups")
        label.pack(pady=10)

        if not self.p2p.peers:
            label = tk.Label(self.current_frame, text="No peers or groups connected")
            label.pack(pady=10)
        else:
            # Listbox to display peers and groups
            listbox = tk.Listbox(self.current_frame)
            for idx, key in enumerate(self.p2p.peers):
                entity = self.p2p.peers[key]
                if entity.is_group:
                    listbox.insert(idx, f"Group - {entity.group_name}")
                else:
                    listbox.insert(idx, f"Peer - {entity.ip}:{entity.port}")
            listbox.pack(pady=10)

            def open_chat():
                # Open chat window with the selected peer or group
                selected_idx = listbox.curselection()
                if selected_idx:
                    selected_item = listbox.get(selected_idx[0])
                    if selected_item.startswith('Group - '):
                        group_name = selected_item[len('Group - '):]
                        selected_entity = self.p2p.peers[group_name]
                    elif selected_item.startswith('Peer - '):
                        addr = selected_item[len('Peer - '):]
                        selected_ip, selected_port = addr.split(':')
                        selected_port = int(selected_port)
                        selected_entity = self.p2p.peers.get((selected_ip, selected_port))
                        if not selected_entity:
                            messagebox.showerror("Error", f"Peer {selected_ip}:{selected_port} is not connected.")
                            return
                    self.open_chat_window(selected_entity)

            # Button to open chat with the selected entity
            open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, entity):
        """
        Opens a chat window for communication with the peer or group.
        """
        if entity.chat_window:
            # Check if the window is already open
            try:
                entity.chat_window.winfo_exists()
                entity.chat_window.lift()
                return
            except tk.TclError:
                # The window no longer exists; reset references
                entity.chat_window = None
                entity.chat_text = None

        # Create a new window for the chat
        chat_window = tk.Toplevel(self.root)
        if entity.is_group:
            title = f"Chat with Group '{entity.group_name}'"
        else:
            title = f"Chat with Peer {entity.ip}:{entity.port}"
        chat_window.title(title)
        chat_window.geometry("500x500")

        # Main frame for the chat window
        main_frame = tk.Frame(chat_window)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Chat history text area
        chat_text = tk.Text(main_frame, height=20, width=60)
        chat_text.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        chat_text.config(state=tk.DISABLED)

        # Load chat history from the cloud database
        self.load_chat_from_cloud(entity, chat_text)

        # Frame for message entry and buttons
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        # Back button to close the chat window
        back_button = tk.Button(bottom_frame, text="Back", command=lambda: self.close_chat_window(entity))
        back_button.pack(side=tk.LEFT, padx=5, pady=5)

        # Message entry field
        message_var = tk.StringVar()
        message_entry = tk.Entry(bottom_frame, textvariable=message_var)
        message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0), pady=5)

        # Send button to send messages
        send_button = tk.Button(bottom_frame, text="Send", command=lambda: self.p2p.send_message(entity, message_var))
        send_button.pack(side=tk.RIGHT, padx=(0, 5), pady=5)

        # Bind Enter key to send message
        message_entry.bind('<Return>', lambda event: self.p2p.send_message(entity, message_var))

        # Store references to the chat window and text area
        entity.chat_window = chat_window
        entity.chat_text = chat_text

        def on_close():
            # Handle chat window close event
            self.close_chat_window(entity)

        chat_window.protocol("WM_DELETE_WINDOW", on_close)
        
    def close_chat_window(self, entity):
        """
        Closes the chat window and cleans up references.
        """
        if entity.chat_window:
            entity.chat_window.destroy()
            entity.chat_window = None
            entity.chat_text = None        
        
    def update_chat_window(self, entity, message):
        """
        Updates the chat window with new messages.
        """
        if entity.chat_window:
            text_area = entity.chat_text
            if text_area:
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, message + '\n')
                text_area.config(state=tk.DISABLED)
                text_area.see(tk.END)
                
    def load_chat_from_file(self, peer, text_area):
        """
        Loads the conversation history from a file.
        """
        filename = f"chat_{peer.ip}_{peer.port}.txt"
        if os.path.exists(filename):
            with open(filename, 'r', encoding='utf-8') as f:
                chat_history = f.read()
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, chat_history)
                text_area.config(state=tk.DISABLED)
                
    def load_chat_from_cloud(self, entity, text_area):
        """
        Loads the conversation history from the cloud database.
        """
        if entity.is_group:
            # Load messages from the group's reference in Firebase
            group_id = sanitize_for_firebase_path(entity.group_name)
            group_ref = db.reference(f"groups/{group_id}/messages")
            messages = group_ref.get()
            if messages:
                for key in messages:
                    message_data = messages[key]
                    # Handle both dict and string formats
                    if isinstance(message_data, dict):
                        sender = message_data.get('sender', '')
                        message = message_data.get('message', '')
                    else:
                        sender = ''
                        message = message_data
                    if sender:
                        display_message = f"{sender}: {message}"
                    else:
                        display_message = message
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, display_message + '\n')
                    text_area.config(state=tk.DISABLED)
        else:
            # Load messages from the chat's reference in Firebase
            chat_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}_{sanitize_for_firebase_path(entity.ip)}_{entity.port}"
            chat_ref = db.reference(f"chats/{chat_id}")
            messages = chat_ref.get()
            if messages:
                for key in messages:
                    message_data = messages[key]
                    # Handle both dict and string formats
                    if isinstance(message_data, dict):
                        sender = message_data.get('sender', '')
                        message = message_data.get('message', '')
                    else:
                        sender = ''
                        message = message_data
                    if sender:
                        display_message = f"{sender}: {message}"
                    else:
                        display_message = message
                    text_area.config(state=tk.NORMAL)
                    text_area.insert(tk.END, display_message + '\n')
                    text_area.config(state=tk.DISABLED)                

    def show_recommendations(self):
        """
        Displays personalized recommendations to the user.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Your Recommendations").pack(pady=10)

        # Text area to display recommendations
        recommendations_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        recommendations_text.pack(pady=10)

        # Retrieve recommendations from the database
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        rec_ref = db.reference(f"recommendations/{user_id}")
        recommendation = rec_ref.get()

        recommendations_text.config(state=tk.NORMAL)
        if recommendation:
            recommendations_text.insert(tk.END, recommendation['ad'])
        else:
            recommendations_text.insert(tk.END, "No recommendations at this time.")
        recommendations_text.config(state=tk.DISABLED)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)  
        
    def search_messages(self):
        """
        Allows users to search conversations using keywords without compromising message security.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Search Messages").pack(pady=10)

        # Entry field for keywords
        keyword_var = tk.StringVar()
        keyword_entry = tk.Entry(self.current_frame, textvariable=keyword_var, width=30)
        keyword_entry.pack(pady=5)

        # Text area to display search results
        result_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        result_text.pack(pady=10)

        def perform_search():
            # Perform the search based on input keywords
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
                    result_text.insert(tk.END, "No matching messages found.")
                result_text.config(state=tk.DISABLED)

        # Button to initiate search
        search_button = tk.Button(self.current_frame, text="Search", command=perform_search)
        search_button.pack(pady=5)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)                      