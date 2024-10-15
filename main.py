import socket
import threading

from Packet import Packet


class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port, start_handshake):
        self.id = (my_ip, listen_port)
        self.send_port = send_port
        self.peer_adress = (target_ip, self.send_port)

        self.start_handshake = start_handshake

        # Receiving socket
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)

        # Sending socket (no need to bind, just used for sending)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def handshake(self):
        if self.start_handshake: self.initiate_handshake()
        elif not self.start_handshake: self.expect_handshake()

    def initiate_handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        while retries < max_retries:
            try:
                # send SYN
                SYN_packet = Packet("", seq_num=1, flags=0b001)  # SYN
                self.send_socket.sendto(SYN_packet.concatenate().encode(), self.peer_adress)
                print(f"1. SENT handshake invite: {SYN_packet.concatenate()} (attempt {retries + 1})")
                retries += 1

                # Expect SYN/ACK
                self.receiving_socket.settimeout(retry_interval) #if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1024)
                SYN_ACK_packet = Packet.deconcatenate(data.decode())

                if SYN_ACK_packet.flags == 0b011:  # if SYN/ACK received
                    print(f"2. RECEIVED handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")
                    ACK_packet = Packet("", seq_num=SYN_ACK_packet.ack_num, ack_num=SYN_ACK_packet.seq_num + 1, flags=0b010)  # ACK
                    self.send_socket.sendto(ACK_packet.concatenate().encode(), self.peer_adress)
                    print(f"3. SENT handshake ACK: {ACK_packet.concatenate()}")

                    print("Handshake successful, connection initialized")
                    return

            except socket.timeout:
                print(f"retrying... (attempt {retries + 1})")
                # continue in sending SYN packages

        print("Handshake timeout after maximum retries")
        return #MUST ADD HERE THAT IF TIMEDOUT IT STOPS THE CODE

    def expect_handshake(self):
        while True:
            data, addr = self.receiving_socket.recvfrom(1024)
            SYN_packet = Packet.deconcatenate(data.decode())
            if SYN_packet.flags == 0b001:  # if received SYN
                print(f"Received handshake SYN: {SYN_packet.concatenate()}")

                SYN_ACK_packet = Packet("", seq_num=100, ack_num=SYN_packet.seq_num + 1, flags=0b011)  # send SYN-ACK
                self.send_socket.sendto(SYN_ACK_packet.concatenate().encode(), self.peer_adress)
                print(f"Sent handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")

                data, addr = self.receiving_socket.recvfrom(1024) #recieve ACK
                ACK_packet = Packet.deconcatenate(data.decode())

                if ACK_packet.flags == 0b010:  # if ACK received
                    print("Handshake successful, connection initialized")
                    return

    def receive_messages(self):
        while True:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)

                decoded_message = data.decode()
                packet = Packet(decoded_message)
                print(f"\nReceived from IP>{addr[0]} Port>{addr[1]}: {packet.get_message()}")

            except Exception:
                continue
    def send_message(self):
        while True:
            message = input("Enter message: (!quit to quit) ")
            if message == "!quit":
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
    # if MY_IP < PEERS_IP: start_handshake = True
    # else: start_handshake = False

    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 3000
        PEER_SEND_PORT = 2000
        start_handshake = True
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 2000
        PEER_SEND_PORT = 3000
        start_handshake = False

    peer = Peer(MY_IP, PEERS_IP, PEER_LISTEN_PORT, PEER_SEND_PORT, start_handshake)
    peer.handshake()

    receive_thread = threading.Thread(target=peer.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    peer.send_message()