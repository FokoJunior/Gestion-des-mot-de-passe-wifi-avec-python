import subprocess
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
import threading

class WifiPasswordRetriever:
    def __init__(self, root):
        self.root = root
        self.root.title("Récupérateur de Mots de Passe Wi-Fi")
        self.root.geometry("600x550")  # Augmenter la taille de la fenêtre
        
        # Titre
        title_label = tk.Label(root, text="Générateur de SSID & PASSWORD Wi-Fi  By Foko Junior", font=("Arial", 16))
        title_label.pack(pady=10)

        # Barre de recherche
        search_frame = tk.Frame(root)
        search_frame.pack(pady=10)
        
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        search_button = tk.Button(search_frame, text="Rechercher", command=self.search_ssid)
        search_button.pack(side=tk.LEFT)

        # Cadre pour la Treeview et la barre de défilement
        tree_frame = tk.Frame(root)
        tree_frame.pack(pady=10)

        # Treeview pour afficher les résultats
        self.tree = ttk.Treeview(tree_frame, columns=("SSID", "Mot de passe"), show='headings', height=15)
        self.tree.heading("SSID", text="SSID")
        self.tree.heading("Mot de passe", text="Mot de passe")

        # Définir la largeur des colonnes
        self.tree.column("SSID", width=300)  # Largeur de la colonne SSID
        self.tree.column("Mot de passe", width=250)  # Largeur de la colonne Mot de passe

        self.tree.pack(side=tk.LEFT)

        # Barre de défilement
        self.scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=self.scrollbar.set)

        # Barre de progression
        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=10)

        # Bouton pour récupérer les mots de passe
        fetch_button = tk.Button(root, text="Récupérer les mots de passe", command=self.get_wifi_passwords)
        fetch_button.pack(pady=5)

        # Bouton pour générer un fichier de SSID et mots de passe
        generate_button = tk.Button(root, text="Générer SSID et Mot de passe", command=self.generate_wifi_passwords_file)
        generate_button.pack(pady=5)

    def get_wifi_passwords(self):
        # Démarrez un thread pour éviter de bloquer l'interface
        thread = threading.Thread(target=self._get_wifi_passwords_thread)
        thread.start()

    def _get_wifi_passwords_thread(self):
        for item in self.tree.get_children():
            self.tree.delete(item)  # Effacer les anciennes entrées
        self.progress["value"] = 0

        profiles_data = subprocess.check_output('netsh wlan show profiles', shell=True, text=True, encoding='utf-8')
        profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "Tous les utilisateurs" in line]

        if not profiles:
            messagebox.showinfo("Info", "Aucun profil Wi-Fi trouvé.")
            return

        self.progress["maximum"] = len(profiles)

        for index, profile in enumerate(profiles):
            password = self.get_password_for_profile(profile)
            if password is not None:
                self.tree.insert('', 'end', values=(profile, password))
            self.progress["value"] = index + 1
            self.root.update_idletasks()  # Met à jour l'interface utilisateur

    def get_password_for_profile(self, profile):
        try:
            profile_info = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True, text=True, encoding='utf-8')
            for line in profile_info.splitlines():
                if "Contenu de la clé" in line:
                    return line.split(":")[1].strip()
            return "Pas de mot de passe enregistré (ou réseau ouvert)"
        except subprocess.CalledProcessError:
            return "Impossible de récupérer les informations"

    def search_ssid(self):
        search_term = self.search_var.get().lower()
        for item in self.tree.get_children():
            self.tree.delete(item)  # Effacer les anciennes entrées

        profiles_data = subprocess.check_output('netsh wlan show profiles', shell=True, text=True, encoding='utf-8')
        profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "Tous les utilisateurs" in line]

        if not profiles:
            messagebox.showinfo("Info", "Aucun profil Wi-Fi trouvé.")
            return

        for profile in profiles:
            password = self.get_password_for_profile(profile)
            if password is not None and search_term in profile.lower():
                self.tree.insert('', 'end', values=(profile, password))

    def generate_wifi_passwords_file(self):
        output_file = "wifi_passwords.txt"
        with open(output_file, "w", encoding='utf-8') as file:
            profiles_data = subprocess.check_output('netsh wlan show profiles', shell=True, text=True, encoding='utf-8')
            profiles = [line.split(":")[1].strip() for line in profiles_data.splitlines() if "Tous les utilisateurs" in line]

            if not profiles:
                messagebox.showinfo("Info", "Aucun profil Wi-Fi trouvé.")
                return

            for profile in profiles:
                password = self.get_password_for_profile(profile)
                if password is not None:
                    file.write(f"{profile}: {password}\n")

        messagebox.showinfo("Info", f"Les SSID et mots de passe ont été générés et enregistrés dans '{output_file}'.")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Voulez-vous quitter ?"):
            self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = WifiPasswordRetriever(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)  # Gérer la fermeture de l'application
    root.mainloop()

