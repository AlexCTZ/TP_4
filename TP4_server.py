"""\
GLO-2000 Travail pratique 4 - Serveur
Noms et numéros étudiants:
- Alexandre Caratza         537313802
- Mathis Tremblay           537013851
- Maude Beaulieu-Laliberté  537167666
"""

import hashlib
import hmac
import json
import os
import select
import socket
import sys

import glosocket
import gloutils
import datetime


class Server:
    """Serveur mail @glo2000.ca."""

    def __init__(self) -> None:
        """
        Prépare le socket du serveur `_server_socket`
        et le met en mode écoute.

        Prépare les attributs suivants:
        - `_client_socs` une liste des sockets clients.
        - `_logged_users` un dictionnaire associant chaque
            socket client à un nom d'utilisateur.

        S'assure que les dossiers de données du serveur existent.
        """
        # self._server_socket
        # self._client_socs
        # self._logged_users
        # ...
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind(('', gloutils.APP_PORT))
            self._server_socket.listen()

            self._client_socs = []
            self._logged_users = {}

            os.makedirs(gloutils.SERVER_DATA_DIR, exist_ok=True)
            lost_dir = os.path.join(gloutils.SERVER_DATA_DIR, gloutils.SERVER_LOST_DIR)
            os.makedirs(lost_dir, exist_ok=True)

            print(f"Serveur démarré sur le port {gloutils.APP_PORT}")
        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de l'initialisation du serveur : {e}")
            sys.exit(1)

    def cleanup(self) -> None:
        """Ferme toutes les connexions résiduelles."""
        for client_soc in self._client_socs:
            client_soc.close()
        self._server_socket.close()

    def _accept_client(self) -> None:
        """Accepte un nouveau client."""
        try:
            client_soc, client_addr = self._server_socket.accept()
            self._client_socs.append(client_soc)
            print(f"Client connecté : {client_addr}")
        except OSError as e:
            print(f"Erreur lors de l'acceptation d'un client : {e}")
            raise glosocket.GLOSocketError("Erreur d'acceptation du client") from e

    def _remove_client(self, client_soc: socket.socket) -> None:
        """Retire le client des structures de données et ferme sa connexion."""
        try:
            if client_soc in self._logged_users:
                del self._logged_users[client_soc]
            if client_soc in self._client_socs:
                self._client_socs.remove(client_soc)
            client_soc.close()
            print("Client déconnecté et retiré.")
        except OSError as e:
            print(f"Erreur lors de la suppression du client : {e}")
            raise glosocket.GLOSocketError("Erreur lors de la suppression du client") from e

    def _create_account(self, client_soc: socket.socket,
                        payload: gloutils.AuthPayload
                        ) -> gloutils.GloMessage:
        """
        Crée un compte à partir des données du payload.

        Si les identifiants sont valides, créee le dossier de l'utilisateur,
        associe le socket au nouvel l'utilisateur et retourne un succès,
        sinon retourne un message d'erreur.
        """
        username = payload['username']
        password = payload['password']

        if not username.replace('.', '').replace('_', '').replace('-', '').isalnum():
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Nom d'utilisateur invalide."}
            )
        if len(password) < 10 or not any(c.isdigit() for c in password) \
                or not any(c.islower() for c in password) or not any(c.isupper() for c in password):
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Mot de passe non sécurisé."}
            )

        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username.lower())
        if os.path.exists(user_dir):
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Nom d'utilisateur déjà pris."}
            )

        try:
            os.makedirs(user_dir)
            hashed_password = hashlib.sha3_512(password.encode('utf-8')).hexdigest()
            with open(os.path.join(user_dir, gloutils.PASSWORD_FILENAME), 'w') as f:
                f.write(hashed_password)
            self._logged_users[client_soc] = username.lower()
            return gloutils.GloMessage(header=gloutils.Headers.OK)
        except OSError as e:
            print(f"Erreur lors de la création du compte : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de la création du compte."}
            )

    def _login(self, client_soc: socket.socket, payload: gloutils.AuthPayload
               ) -> gloutils.GloMessage:
        """
        Vérifie que les données fournies correspondent à un compte existant.

        Si les identifiants sont valides, associe le socket à l'utilisateur et
        retourne un succès, sinon retourne un message d'erreur.
        """
        username = payload['username'].lower()
        password = payload['password']

        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username)
        password_file = os.path.join(user_dir, gloutils.PASSWORD_FILENAME)

        if not os.path.exists(user_dir) or not os.path.isfile(password_file):
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Nom d'utilisateur ou mot de passe invalide."}
            )

        try:
            with open(password_file, 'r') as f:
                stored_password_hash = f.read().strip()
            input_password_hash = hashlib.sha3_512(password.encode('utf-8')).hexdigest()

            if not hmac.compare_digest(stored_password_hash, input_password_hash):
                return gloutils.GloMessage(
                    header=gloutils.Headers.ERROR,
                    payload={"error_message": "Nom d'utilisateur ou mot de passe invalide."}
                )

            self._logged_users[client_soc] = username
            return gloutils.GloMessage(header=gloutils.Headers.OK)

        except OSError as e:
            print(f"Erreur lors de la connexion : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de la connexion."}
            )

    def _logout(self, client_soc: socket.socket) -> None:
        try:
            if client_soc in self._logged_users:
                del self._logged_users[client_soc]
                print(f"Utilisateur déconnecté : {client_soc.getpeername()}")
        except OSError as e:
            print(f"Erreur lors de la déconnexion : {e}")
            raise glosocket.GLOSocketError("Erreur lors de la déconnexion") from e

    def _get_email_list(self, client_soc: socket.socket
                        ) -> gloutils.GloMessage:
        """
        Récupère la liste des courriels de l'utilisateur associé au socket.
        Les éléments de la liste sont construits à l'aide du gabarit
        SUBJECT_DISPLAY et sont ordonnés du plus récent au plus ancien.

        Une absence de courriel n'est pas une erreur, mais une liste vide.
        """
        username = self._logged_users.get(client_soc)
        if not username:
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Utilisateur non connecté."}
            )

        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username)
        try:
            email_files = sorted(
                [f for f in os.listdir(user_dir) if f.endswith('.json')],
                reverse=True
            )
            email_list = []
            for i, email_file in enumerate(email_files, start=1):
                with open(os.path.join(user_dir, email_file), 'r') as f:
                    email_data = json.load(f)
                email_list.append(
                    gloutils.SUBJECT_DISPLAY.format(
                        number=i,
                        sender=email_data['sender'],
                        subject=email_data['subject'],
                        date=email_data['date']
                    )
                )

            return gloutils.GloMessage(
                header=gloutils.Headers.OK,
                payload={"email_list": email_list}
            )
        except OSError as e:
            print(f"Erreur lors de la récupération de la liste des courriels : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de la récupération des courriels."}
            )

    def _get_email(self, client_soc: socket.socket,
                   payload: gloutils.EmailChoicePayload
                   ) -> gloutils.GloMessage:
        """
        Récupère le contenu de l'email dans le dossier de l'utilisateur associé
        au socket.
        """
        username = self._logged_users.get(client_soc)
        if not username:
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Utilisateur non connecté."}
            )

        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username)
        try:
            email_files = sorted(
                [f for f in os.listdir(user_dir) if f.endswith('.json')],
                reverse=True
            )

            choice = payload.get('choice')
            if not 1 <= choice <= len(email_files):
                return gloutils.GloMessage(
                    header=gloutils.Headers.ERROR,
                    payload={"error_message": "Choix invalide."}
                )

            email_file = email_files[choice - 1]
            with open(os.path.join(user_dir, email_file), 'r') as f:
                email_data = json.load(f)

            return gloutils.GloMessage(
                header=gloutils.Headers.OK,
                payload=email_data
            )
        except (OSError, json.JSONDecodeError) as e:
            print(f"Erreur lors de la récupération du courriel : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de la récupération du courriel."}
            )

    def _get_stats(self, client_soc: socket.socket) -> gloutils.GloMessage:
        """
        Récupère le nombre de courriels et la taille du dossier et des fichiers
        de l'utilisateur associé au socket.
        """
        username = self._logged_users.get(client_soc)
        if not username:
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Utilisateur non connecté."}
            )

        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username)
        try:
            email_files = [f for f in os.listdir(user_dir) if f.endswith('.json')]
            total_size = sum(
                os.path.getsize(os.path.join(user_dir, f)) for f in email_files
            )

            return gloutils.GloMessage(
                header=gloutils.Headers.OK,
                payload={
                    "count": len(email_files),
                    "size": total_size
                }
            )
        except OSError as e:
            print(f"Erreur lors de la récupération des statistiques : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de la récupération des statistiques."}
            )

    def _send_email(self, payload: gloutils.EmailContentPayload
                    ) -> gloutils.GloMessage:
        """
        Détermine si l'envoi est interne ou externe et:
        - Si l'envoi est interne, écris le message tel quel dans le dossier
        du destinataire.
        - Si le destinataire n'existe pas, place le message dans le dossier
        SERVER_LOST_DIR et considère l'envoi comme un échec.
        - Si le destinataire est externe, considère l'envoi comme un échec.

        Retourne un messange indiquant le succès ou l'échec de l'opération.
        """
        destination = payload['destination']
        if not destination.endswith(f"@{gloutils.SERVER_DOMAIN}"):
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Destinataire externe non autorisé."}
            )

        username = destination.split('@')[0].lower()
        user_dir = os.path.join(gloutils.SERVER_DATA_DIR, username)

        try:
            if os.path.exists(user_dir):
                email_filename = os.path.join(
                    user_dir, f"email_{int(datetime.datetime.now().timestamp())}.json"
                )
                with open(email_filename, 'w') as f:
                    json.dump(payload, f)
                return gloutils.GloMessage(header=gloutils.Headers.OK)
            else:
                lost_dir = os.path.join(gloutils.SERVER_DATA_DIR, gloutils.SERVER_LOST_DIR)
                email_filename = os.path.join(
                    lost_dir, f"lost_email_{int(datetime.datetime.now().timestamp())}.json"
                )
                with open(email_filename, 'w') as f:
                    json.dump(payload, f)
                return gloutils.GloMessage(
                    header=gloutils.Headers.ERROR,
                    payload={"error_message": "Destinataire introuvable. Courriel perdu."}
                )
        except OSError as e:
            print(f"Erreur lors de l'envoi du courriel : {e}")
            return gloutils.GloMessage(
                header=gloutils.Headers.ERROR,
                payload={"error_message": "Erreur système lors de l'envoi du courriel."}
            )

    def run(self):
        """Point d'entrée du serveur."""
        try:
            print("Le serveur est prêt à accepter des connexions.")
            while True:
                readable, _, _ = select.select(
                    [self._server_socket] + self._client_socs, [], []
                )

                for soc in readable:
                    if soc is self._server_socket:
                        self._accept_client()
                    else:
                        try:
                            message = glosocket.recv_mesg(soc)
                            message_data = json.loads(message)

                            header = message_data.get("header")
                            payload = message_data.get("payload", {})

                            if header == gloutils.Headers.AUTH_REGISTER:
                                response = self._create_account(soc, payload)
                            elif header == gloutils.Headers.AUTH_LOGIN:
                                response = self._login(soc, payload)
                            elif header == gloutils.Headers.AUTH_LOGOUT:
                                self._logout(soc)
                                response = gloutils.GloMessage(header=gloutils.Headers.OK)
                            elif header == gloutils.Headers.INBOX_READING_REQUEST:
                                response = self._get_email_list(soc)
                            elif header == gloutils.Headers.INBOX_READING_CHOICE:
                                response = self._get_email(soc, payload)
                            elif header == gloutils.Headers.EMAIL_SENDING:
                                response = self._send_email(payload)
                            elif header == gloutils.Headers.STATS_REQUEST:
                                response = self._get_stats(soc)
                            elif header == gloutils.Headers.BYE:
                                self._remove_client(soc)
                                continue
                            else:
                                response = gloutils.GloMessage(
                                    header=gloutils.Headers.ERROR,
                                    payload={"error_message": "Requête invalide."}
                                )

                            glosocket.snd_mesg(soc, json.dumps(response))

                        except glosocket.GLOSocketError as e:
                            print(f"Erreur de communication avec un client : {e}")
                            self._remove_client(soc)
                        except json.JSONDecodeError as e:
                            print(f"Erreur de format JSON : {e}")
                            self._remove_client(soc)

        except KeyboardInterrupt:
            print("\nArrêt du serveur demandé.")
        finally:
            self.cleanup()


def _main() -> int:
    server = Server()
    try:
        server.run()
    except KeyboardInterrupt:
        server.cleanup()
    return 0


if __name__ == '__main__':
    sys.exit(_main())
