"""\
GLO-2000 Travail pratique 4 - Client
Noms et numéros étudiants:
- Alexandre Caratza         537313802
- Mathis Tremblay           537013851
- Maude Beaulieu-Laliberté  537167666
"""

import argparse
import getpass
import json
import socket
import sys

import glosocket
import gloutils
import datetime

class Client:
    """Client pour le serveur mail @glo2000.ca."""

    def __init__(self, destination: str) -> None:
        """
        Prépare et connecte le socket du client `_socket`.

        Prépare un attribut `_username` pour stocker le nom d'utilisateur
        courant. Laissé vide quand l'utilisateur n'est pas connecté.
        """
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((destination, gloutils.APP_PORT))
            self._username = ""
            print(f"Connecté au serveur à {destination}:{gloutils.APP_PORT}")
        except (socket.error, glosocket.GLOSocketError) as e:
            print(f"Erreur lors de la connexion au serveur : {e}")
            sys.exit(1)

    def _register(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_REGISTER`.

        Si la création du compte s'est effectuée avec succès, l'attribut
        `_username` est mis à jour, sinon l'erreur est affichée.
        """
        username = input("Entrez un nom d'utilisateur : ")
        password = getpass.getpass("Entrez un mot de passe : ")

        payload = {"username": username, "password": password}
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.AUTH_REGISTER,
                "payload": payload
            }))
            response = json.loads(glosocket.recv_mesg(self._socket))

            if response["header"] == gloutils.Headers.OK:
                print("Compte créé avec succès.")
                self._username = username
            else:
                print(f"Erreur : {response['payload']['error_message']}")
        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la création du compte : {e}")

    def _login(self) -> None:
        """
        Demande un nom d'utilisateur et un mot de passe et les transmet au
        serveur avec l'entête `AUTH_LOGIN`.

        Si la connexion est effectuée avec succès, l'attribut `_username`
        est mis à jour, sinon l'erreur est affichée.
        """
        username = input("Entrez votre nom d'utilisateur : ")
        password = getpass.getpass("Entrez votre mot de passe : ")

        payload = {"username": username, "password": password}
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.AUTH_LOGIN,
                "payload": payload
            }))
            response = json.loads(glosocket.recv_mesg(self._socket))

            if response["header"] == gloutils.Headers.OK:
                print("Connexion réussie.")
                self._username = username
            else:
                print(f"Erreur : {response['payload']['error_message']}")
        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la connexion : {e}")

    def _quit(self) -> None:
        """
        Préviens le serveur de la déconnexion avec l'entête `BYE` et ferme le
        socket du client.
        """
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.BYE
            }))
            print("Déconnexion du serveur...")
        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la déconnexion : {e}")
        finally:
            self._socket.close()
            print("Client déconnecté. Au revoir !")
            sys.exit(0)

    def _read_email(self) -> None:
        """
        Demande au serveur la liste de ses courriels avec l'entête
        `INBOX_READING_REQUEST`.

        Affiche la liste des courriels puis transmet le choix de l'utilisateur
        avec l'entête `INBOX_READING_CHOICE`.

        Affiche le courriel à l'aide du gabarit `EMAIL_DISPLAY`.

        S'il n'y a pas de courriel à lire, l'utilisateur est averti avant de
        retourner au menu principal.
        """
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.INBOX_READING_REQUEST
            }))
            response = json.loads(glosocket.recv_mesg(self._socket))

            if response["header"] == gloutils.Headers.OK:
                email_list = response["payload"]["email_list"]
                if not email_list:
                    print("Aucun courriel à afficher.")
                    return

                print("\nListe des courriels :")
                for email in email_list:
                    print(email)

                choice = input("Entrez le numéro du courriel à lire : ").strip()
                if not choice.isdigit():
                    print("Entrée invalide.")
                    return

                payload = {"choice": int(choice)}
                glosocket.snd_mesg(self._socket, json.dumps({
                    "header": gloutils.Headers.INBOX_READING_CHOICE,
                    "payload": payload
                }))

                response = json.loads(glosocket.recv_mesg(self._socket))
                if response["header"] == gloutils.Headers.OK:
                    email_data = response["payload"]
                    print("\n" + gloutils.EMAIL_DISPLAY.format(
                        sender=email_data["sender"],
                        to=email_data["destination"],
                        subject=email_data["subject"],
                        date=email_data["date"],
                        body=email_data["content"]
                    ))
                else:
                    print(f"Erreur : {response['payload']['error_message']}")
            else:
                print(f"Erreur : {response['payload']['error_message']}")

        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la consultation des courriels : {e}")

    def _send_email(self) -> None:
        """
        Demande à l'utilisateur respectivement:
        - l'adresse email du destinataire,
        - le sujet du message,
        - le corps du message.

        La saisie du corps se termine par un point seul sur une ligne.

        Transmet ces informations avec l'entête `EMAIL_SENDING`.
        """
        try:
            destination = input("Entrez l'adresse email du destinataire : ").strip()
            subject = input("Entrez le sujet du courriel : ").strip()
            print("Entrez le contenu du courriel. Terminez avec un '.' seul sur une ligne :")

            content_lines = []
            while True:
                line = input()
                if line == ".":
                    break
                content_lines.append(line)
            content = "\n".join(content_lines)

            payload = {
                "sender": f"{self._username}@{gloutils.SERVER_DOMAIN}",
                "destination": destination,
                "subject": subject,
                "date": gloutils.get_current_utc_time(),
                "content": content
            }
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.EMAIL_SENDING,
                "payload": payload
            }))

            response = json.loads(glosocket.recv_mesg(self._socket))
            if response["header"] == gloutils.Headers.OK:
                print("Courriel envoyé avec succès.")
            else:
                print(f"Erreur : {response['payload']['error_message']}")

        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de l'envoi du courriel : {e}")

    def _check_stats(self) -> None:
        """
        Demande les statistiques au serveur avec l'entête `STATS_REQUEST`.

        Affiche les statistiques à l'aide du gabarit `STATS_DISPLAY`.
        """
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.STATS_REQUEST
            }))
            response = json.loads(glosocket.recv_mesg(self._socket))

            if response["header"] == gloutils.Headers.OK:
                stats = response["payload"]
                print(gloutils.STATS_DISPLAY.format(
                    count=stats["count"],
                    size=stats["size"]
                ))
            else:
                print(f"Erreur : {response['payload']['error_message']}")

        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la consultation des statistiques : {e}")

    def _logout(self) -> None:
        """
        Préviens le serveur avec l'entête `AUTH_LOGOUT`.

        Met à jour l'attribut `_username`.
        """
        try:
            glosocket.snd_mesg(self._socket, json.dumps({
                "header": gloutils.Headers.AUTH_LOGOUT
            }))
            self._username = ""
            print("Déconnexion réussie.")
        except glosocket.GLOSocketError as e:
            print(f"Erreur lors de la déconnexion : {e}")

    def run(self) -> None:
        """Point d'entrée du client."""
        should_quit = False

        while not should_quit:
            try:
                if not self._username:
                    print(gloutils.CLIENT_AUTH_CHOICE)
                    choice = input("Entrez votre choix [1-3] : ").strip()
                    if choice == "1":
                        self._register()
                    elif choice == "2":
                        self._login()
                    elif choice == "3":
                        print("Au revoir")
                        should_quit = True
                    else:
                        print("Choix invalide.")
                else:
                    print(gloutils.CLIENT_USE_CHOICE)
                    choice = input("Entrez votre choix [1-4] : ").strip()
                    if choice == "1":
                        self._read_email()
                    elif choice == "2":
                        self._send_email()
                    elif choice == "3":
                        self._check_stats()
                    elif choice == "4":
                        self._logout()
                    else:
                        print("Choix invalide.")
            except KeyboardInterrupt:
                print("\nArrêt du client demandé.")
                should_quit = True
            except Exception as e:
                print(f"Erreur inattendue : {e}")


def _main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--destination", action="store",
                        dest="dest", required=True,
                        help="Adresse IP/URL du serveur.")
    args = parser.parse_args(sys.argv[1:])
    client = Client(args.dest)
    client.run()
    return 0


if __name__ == '__main__':
    sys.exit(_main())
