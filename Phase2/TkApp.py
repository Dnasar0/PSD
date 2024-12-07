# TkApp.py
import json
import tkinter as tk
from tkinter import messagebox
import threading
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

        # Add Topics of Interest button
        self.topics_button = tk.Button(self.current_frame, text="Topics of Interest", command=self.show_topics_window)
        self.topics_button.pack(pady=10)

        # Button to view personalized advertisements
        self.recommendations_button = tk.Button(self.current_frame, text="View Recommendations", command=self.show_recommendations)
        self.recommendations_button.pack(pady=10)

    def show_topics_window(self):
        """
        Displays the topics selection in the same window.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Select Topics of Interest").pack(pady=10)

        # List of topics
        topics = ["Cars", "Music", "Soccer", "Basketball", "Cybersecurity", "AI-Artificial Intelligence", "IoT-Internet of Things"]

        # Dictionary to hold the topic variables
        self.topic_vars = {}
        for topic in topics:
            var = tk.IntVar()
            self.topic_vars[topic] = var
            cb = tk.Checkbutton(self.current_frame, text=topic, variable=var)
            cb.pack(anchor=tk.W)

        # Attempt to load the user's existing topics from Firebase
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        
        for replica in self.p2p.getFirebaseRefs():
        
            user_ref = db.reference(f"{replica}/users/{user_id}")

            try:
                user_data = user_ref.get()
                if user_data and 'topics' in user_data:
                    selected_topics = user_data['topics']
                else:
                    selected_topics = []
                    raise Exception("No topics found in Firebase")
            except Exception as e:
                print(f"Error fetching topics from Firebase: {e}")
                # If Firebase fails, try fetching from AWS S3
                
                for s3_bucket_name in self.p2p.getS3BucketNames():
                
                    selected_topics = self.get_topics_from_s3(user_id, s3_bucket_name)

            # Now update the UI with the selected topics
            for topic in selected_topics:
                if topic in self.topic_vars:
                    self.topic_vars[topic].set(1)

        # Save button
        save_button = tk.Button(self.current_frame, text="Save", command=self.p2p.save_topics)
        save_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def get_topics_from_s3(self, user_id, s3_bucket_name):
        """
        Fetches the user's topics from AWS S3 if Firebase is unavailable.
        """
        try:
            s3_key = f"users/{user_id}.json"
            response = self.p2p.s3_client.get_object(
                Bucket=s3_bucket_name,
                Key=s3_key
            )
            topics_data = json.loads(response['Body'].read())
            print(f"Fetched topics for user {user_id} from S3.")
            return topics_data.get('topics', [])
        except Exception as e:
            print(f"Error fetching topics from S3: {e}")
            messagebox.showerror("Error", "Unable to load topics from both Firebase and S3.")
            return []


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

        # Initially show peer inputs
        self.peer_inputs_frame.pack()

        # Button to initiate connection
        self.connect_peer_button = tk.Button(
            self.current_frame,
            text="Connect",
            command=self.connect_to_selected_entity
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
            # Instead of group name entry, show list of groups
            self.show_group_selection()

    def show_group_selection(self):
        """
        Displays a list of group names in the user's topics of interest.
        Checks both Firebase and AWS S3 and shows the one with more groups if they differ.
        """
        # Clear group_inputs_frame
        for widget in self.group_inputs_frame.winfo_children():
            widget.destroy()

        # Get user's topics
        user_id = f"{sanitize_for_firebase_path(self.host)}_{self.port}"
        
        for replica in self.p2p.getFirebaseRefs():
            
                user_ref = db.reference(f"{replica}/users/{user_id}")
    
                try:
                    user_data = user_ref.get()
                    if user_data and 'topics' in user_data:
                        user_topics = user_data['topics']
                    else:
                        user_topics = []
                        raise Exception("No topics found in Firebase")
                except Exception as e:
                    print(f"Error fetching user topics from Firebase: {e}")
                    # If Firebase fails, fall back to getting topics from S3
                    
                    for s3_bucket_name in self.p2p.getS3BucketNames():
                        
                        user_topics = self.get_topics_from_s3(user_id, s3_bucket_name)

        if not user_topics:
            messagebox.showerror("Error", "You have not selected any topics of interest. Please select topics before connecting to groups.")
            return

        # Get group names from Firebase
        firebase_groups = self.get_group_names_from_firebase(user_topics)
        
        # Get group names from S3
        s3_groups = self.get_group_names_from_s3(user_topics)

        # Compare the number of groups from Firebase and S3
        if len(firebase_groups) > len(s3_groups):
            print("Firebase has more groups. Displaying Firebase groups.")
            available_groups = firebase_groups
        elif len(firebase_groups) < len(s3_groups):
            print("S3 has more groups. Displaying S3 groups.")
            available_groups = s3_groups
        else:
            print("Both Firebase and S3 have the same number of groups. Displaying either.")
            available_groups = firebase_groups  # Or s3_groups, as they're the same length

        # Display the available groups (whether from Firebase or S3)
        label = tk.Label(self.group_inputs_frame, text="Select a Group:")
        label.pack()

        self.group_listbox = tk.Listbox(self.group_inputs_frame)
        if available_groups:
            for idx, group_name in enumerate(available_groups):
                self.group_listbox.insert(idx, group_name)
        else:
            self.group_listbox.insert(0, "No groups available in your topics of interest.")
            self.group_listbox.config(state=tk.DISABLED)

        self.group_listbox.pack()

        # Button to create a new group
        create_group_button = tk.Button(self.group_inputs_frame, text="Create New Group", command=self.p2p.create_new_group)
        create_group_button.pack(pady=5)

        self.group_inputs_frame.pack()

    def get_group_names_from_firebase(self, user_topics):
        """
        Fetches group names from Firebase based on the user's topics.
        """
        groups = []
        
        for replica in self.p2p.getFirebaseRefs():
            
            try:
                groups_ref = db.reference(f"{replica}/groups")
                groups_data = groups_ref.get()  # Get all groups in Firebase
                if groups_data:
                    for group_name, group_info in groups_data.items():
                        group_topic = group_info.get('topic')  # Get the group topic
                        if group_topic in user_topics:
                            groups.append(group_name)  # Add group name if topic matches
            except Exception as e:
                print(f"Error fetching groups from Firebase: {e}")
            return list(dict.fromkeys(groups)) 

    def get_group_names_from_s3(self, user_topics):
        """
        Fetches group names from AWS S3 based on the user's topics.
        """
        groups = []
        
        for s3_bucket_name in self.p2p.getS3BucketNames():
        
            try:
                # List all objects (files) in the 'groups' directory of the S3 bucket
                s3_objects = self.p2p.s3_client.list_objects_v2(
                    Bucket=s3_bucket_name,
                    Prefix="groups/"
                )

                # Check if there are any objects in the S3 bucket
                if 'Contents' in s3_objects:
                    for obj in s3_objects['Contents']:
                        group_name = obj['Key'].replace("groups/", "").replace(".json", "")  # Get the group name from the filename
                        s3_key = obj['Key']  # The S3 object key (filename)

                        # Fetch the group data from S3
                        response = self.p2p.s3_client.get_object(
                            Bucket=s3_bucket_name,
                            Key=s3_key
                        )
                        group_data = json.loads(response['Body'].read())
                        group_topic = group_data.get('topic')  # Get the group topic from the S3 file

                        # Add the group name if the topic matches
                        if group_topic in user_topics:
                            groups.append(group_name)
            except Exception as e:
                print(f"Error fetching groups from S3: {e}")
        return list(dict.fromkeys(groups))
   

    def connect_to_selected_entity(self):
        """
        Connects to the selected peer or group based on the inputs.
        """
        connection_type = self.connection_type_var.get()
        if connection_type == 'peer':
            # Get IP and port from input fields
            peer_ip = self.peer_ip_entry.get()
            peer_port = self.peer_port_entry.get()

            # Input validation for IP and port
            if not self.p2p.validate_ip(peer_ip) or not peer_port.isdigit():
                messagebox.showerror("Error", "Invalid IP or port!")
                return

            peer_port = int(peer_port)

            if (peer_ip, peer_port) in self.p2p.peers:
                messagebox.showinfo("Info", f"Already connected to {peer_ip}:{peer_port}")
                return

            # Start a thread to connect to the peer and update UI
            threading.Thread(target=self.p2p.connect_to_peer_ui, args=(peer_ip, peer_port), daemon=True).start()

        elif connection_type == 'group':
            # Get the selected group from the listbox
            selected_idx = self.group_listbox.curselection()
            if selected_idx:
                group_name = self.group_listbox.get(selected_idx[0])
                self.p2p.connect_to_group(group_name)
            else:
                messagebox.showerror("Error", "No group selected.")

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
                        formatted_ip = None
                        selected_port = None
                    elif selected_item.startswith('Peer - '):
                        addr = selected_item[len('Peer - '):]
                        selected_ip, selected_port = addr.split(':')
                        selected_port = int(selected_port)
                        selected_entity = self.p2p.peers.get((selected_ip, selected_port))
                        formatted_ip = selected_ip.replace('.', '_')
                        if not selected_entity:
                            messagebox.showerror("Error", f"Peer {selected_ip}:{selected_port} is not connected.")
                            return
                    self.open_chat_window(selected_entity, formatted_ip ,selected_port)

            # Button to open chat with the selected entity
            open_chat_button = tk.Button(self.current_frame, text="Open Chat", command=open_chat)
            open_chat_button.pack(pady=10)

        # Back button to return to main menu
        back_button = tk.Button(self.current_frame, text="Back", command=self.setup_main_menu)
        back_button.pack(pady=10)

    def open_chat_window(self, entity, peer_ip=None, peer_port=None):
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

        # Load chat history from the cloud databases
        self.load_chat_from_cloud(entity, chat_text, peer_ip, peer_port)

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

    def load_chat_from_cloud(self, entity, text_area, peer_ip=None, peer_port=None):
        """
        Loads the conversation history from the cloud databases.
        """
        messages = self.p2p.load_messages_from_cloud(entity, peer_ip, peer_port)
        if messages:
            for message in messages:
                text_area.config(state=tk.NORMAL)
                text_area.insert(tk.END, message + '\n')
                text_area.config(state=tk.DISABLED)

    def show_recommendations(self):
        """
        Displays personalized advertisements to the user in a privacy-preserving manner.
        """
        self.clear_frame()

        tk.Label(self.current_frame, text="Your Personalized Advertisements").pack(pady=10)

        # Text area to display recommendations
        recommendations_text = tk.Text(self.current_frame, height=15, width=60, state=tk.DISABLED)
        recommendations_text.pack(pady=10)

        try:
            # Retrieve recommended ads from the P2PChatApp
            recommended_ads = self.p2p.get_recommendations()

            recommendations_text.config(state=tk.NORMAL)
            if recommended_ads:
                for ad in recommended_ads:
                    recommendations_text.insert(tk.END, f"Ad: {ad['text']}\n\n")
            else:
                recommendations_text.insert(tk.END, "No advertisements at this time.\n")
            recommendations_text.config(state=tk.DISABLED)
        except Exception as e:
            # Handle exceptions
            messagebox.showerror("Error", f"An error occurred while fetching advertisements:\n{e}")
            self.setup_main_menu()
            return

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
        keyword_entry.focus_set()  # Ensure the entry widget accepts input

        # Text area to display search results
        result_text = tk.Text(self.current_frame, height=15, width=60)
        result_text.pack(pady=10)
        result_text.config(state=tk.DISABLED)

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
