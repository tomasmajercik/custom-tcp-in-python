import socket
import threading

from Packet import Packet


class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        self.id = (my_ip, listen_port)
        self.send_port = send_port
        self.peer_adress = (target_ip, self.send_port)

        # Receiving socket
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind((my_ip, listen_port))

        # Sending socket (no need to bind, just used for sending)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def receive_messages(self):
        while True:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)

                decoded_message = data.decode()
                packet = Packet(decoded_message)
                print(f"\nReceived from IP>{addr[0]} Port>{addr[1]}: {packet.get_message()}")

            except Exception as e:
                print(f"Error recieving message: {e}")
                break

    def send_message(self):
        while True:
            message = input("Enter message: (!quit to quit) ")
            if message == "!quit":
                self.send_port.close()
                self.receiving_socket.close()
                break

            packet = Packet(message) #build a packet
            try:
                self.send_socket.sendto(packet.concatenate().encode(), self.peer_adress) #sprav classu packet kde bude cely header
            except Exception as e:
                print(f"Error sending message to {peer}: {e}")




if __name__ == '__main__':

    MY_IP = "localhost"
    # PEERS_IP = input("Enter PEER's IP address: ")
    # PEER_SEND_PORT = int(input("Enter your send port (should be the same as second's peer listening port): "))
    # PEER_LISTEN_PORT = int(input("Enter your listening port (should be the same as second's peer sending port): "))

    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 3000
        PEER_SEND_PORT = 2000
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 2000
        PEER_SEND_PORT = 3000

    peer = Peer(MY_IP, PEERS_IP, PEER_LISTEN_PORT, PEER_SEND_PORT)

    receive_thread = threading.Thread(target=peer.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    peer.send_message()

    #65% 16:42