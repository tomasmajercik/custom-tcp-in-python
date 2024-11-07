import socket
import threading
import random
from Packet import Packet
from MessageHandler import MessageHandler
from ConnectionsHandler import ConnectionsHandler


class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        self.id = (my_ip, listen_port)
        self.peer_address = (target_ip, send_port)

        # Initialize sockets
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.seq_num = random.randint(0, 1000)
        self.ack_num = 0
        self.freeze_loops = False
        self.kill_communication = False

        # Handlers
        self.connections_handler = ConnectionsHandler(self)
        self.message_handler = MessageHandler(self)

    def start_communication(self):
        # Establish connection
        if not self.connections_handler.handshake():
            print("Failed to establish connection. Exiting.")
            return

        # Start receiving messages in a separate thread
        receive_thread = threading.Thread(target=self.message_handler.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

        self.show_menu()

    def show_menu(self):
        while not self.kill_communication:
            choice = input("\nMENU: 'm' for message | 'f' for file | '!quit' to quit\nChoose an option: ").strip()
            if choice == 'm':
                message = input("Enter message: ").strip()
                self.message_handler.send_message(message)
            elif choice == '!quit':
                self.freeze_loops = True
                self.connections_handler.start_terminate_connection()
                break
            else:
                print("Invalid choice. Please try again.")


if __name__ == '__main__':
    # Setup peer information
    MY_IP = "localhost"
    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 8000
        PEER_SEND_PORT = 7000
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 7000
        PEER_SEND_PORT = 8000

    # Start peer
    peer = Peer(MY_IP, PEERS_IP, PEER_LISTEN_PORT, PEER_SEND_PORT)
    peer.start_communication()
