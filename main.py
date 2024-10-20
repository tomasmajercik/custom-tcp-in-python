import socket
import threading
import random

from Packet import Packet


class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port, start_handshake):
        self.id = (my_ip, listen_port)
        self.send_port = send_port
        self.peer_address = (target_ip, self.send_port)

        self.start_handshake = start_handshake

        # Receiving socket
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)

        # Sending socket (no need to bind, just used for sending)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.seq_num = random.randint(0, 1000)
        self.ack_num = 0

        self.stop_and_wait = False

    def handshake(self):
        if self.start_handshake:
            return self.initiate_handshake()
        elif not self.start_handshake:
            return self.expect_handshake()

    def initiate_handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        # ! dohodnut checksum
        # ! spravit aby davalo zmysel mat syn a ack num
        # ! prvy seq by mal byt random a preco tam mam 100

        while retries < max_retries:
            try:
                # send SYN
                SYN_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b001)  # SYN
                self.send_socket.sendto(SYN_packet.concatenate().encode(), self.peer_address)
                print(f"\n1. SENT handshake invite: {SYN_packet.concatenate()} (attempt {retries + 1})")
                retries += 1

                # Expect SYN/ACK
                self.receiving_socket.settimeout(retry_interval)  # if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1024)

                SYN_ACK_packet = Packet.deconcatenate(data.decode())

                if SYN_ACK_packet.flags == 0b011:  # if SYN/ACK received
                    print(f"2. RECEIVED handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")
                    self.seq_num += 1  # sent one phantom byte
                    self.ack_num = SYN_ACK_packet.seq_num + 1  # Update ACK number to one more than received seq num
                    ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b010)  # ACK

                    self.send_socket.sendto(ACK_packet.concatenate().encode(), self.peer_address)
                    print(f"3. SENT handshake ACK: {ACK_packet.concatenate()}")
                    self.seq_num += 1  # after succesfull handshake, "I am waiting for this package"

                    print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                    return True

            except socket.timeout:
                print(f"retrying... (attempt {retries + 1})")
                # continue in sending SYN packages

        print(f"Handshake timeout after {max_retries} retries")
        self.receiving_socket.close()
        return False
    def expect_handshake(self):
        max_time_duration = 30
        self.receiving_socket.settimeout(max_time_duration)
        # ! dohodnut checksum
        try:
            while True:
                data, addr = self.receiving_socket.recvfrom(1024)
                SYN_packet = Packet.deconcatenate(data.decode())
                if SYN_packet.flags == 0b001:  # if received SYN
                    print(f"\n1. Received handshake SYN: {SYN_packet.concatenate()}")
                    self.ack_num = SYN_packet.seq_num + 1

                    SYN_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b011)  # send SYN-ACK
                    self.send_socket.sendto(SYN_ACK_packet.concatenate().encode(), self.peer_address)
                    print(f"2. Sent handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")

                    data, addr = self.receiving_socket.recvfrom(1024)  # recieve ACK
                    ACK_packet = Packet.deconcatenate(data.decode())

                    if ACK_packet.flags == 0b010:  # if ACK received
                        print(f"3. Received handshake ACK: {ACK_packet.concatenate()}")
                        self.seq_num += 1
                        self.ack_num += 1
                        print(
                            f"\n##Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                        return True
        except socket.timeout:
            print(f"No handshake for {max_time_duration} seconds, exiting the code")
            return False

    def receive_messages(self):
        while True and not self.stop_and_wait:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)
                packet = Packet.deconcatenate(data.decode())

                if packet.seq_num == self.ack_num:
                    self.ack_num += len(packet.get_message())  # add length of message to my ack_num
                    ack_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b010)
                    self.send_socket.sendto(ack_packet.concatenate().encode(), self.peer_address)

                else:
                    print("Out of order packet received, ignoring")
                    # Send an acknowledgment for the last valid packet
                    # ask for lost package

                # ! ak receivnem SYN pozvanku tu (1 sa odpoji a znova pripoji)

                # print(f"\nReceived from IP>{addr[0]} Port>{addr[1]}: {packet.concatenate()}")
                if packet.flags != 0b010:
                    print(f"Received << {packet.concatenate()}")
                    print(f"#### seq:{self.seq_num} ack:{self.ack_num}")

            except socket.timeout:
                # print("here")
                continue

    def send_message(self):
        while True:
            self.stop_and_wait = False
            message = input("Enter message: (!quit to quit) ").strip()
            if message == "!quit":
                # ! taktiez poslem flag 100 aby som terminoval komunikaciu
                self.receiving_socket.close()
                break

            packet = Packet(message, seq_num=self.seq_num, ack_num=self.ack_num, flags=0b000)  # build a packet
            # Send the packet
            self.send_socket.sendto(packet.concatenate().encode(), self.peer_address)
            self.receiving_socket.settimeout(0) #so the receiving function stops listening
            self.stop_and_wait = True #turn off this pear receiving function

            print(f"Sent >> {packet.concatenate()}")
            self.seq_num += len(message)  # Update seq_num based on message length

            try:  # Wait for acknowledgment
                self.receiving_socket.settimeout(5)
                data, addr = self.receiving_socket.recvfrom(1024)
                ack_packet = Packet.deconcatenate(data.decode())
                if ack_packet.flags == 0b010:  # ACK flag
                    self.ack_num = ack_packet.seq_num  # Update acknowledgment number
            except socket.timeout:
                print("Acknowledgment timeout, resending packet...")


if __name__ == '__main__':

    # MY_IP = input("Enter YOUR IP address: ")
    # PEERS_IP = input("Enter PEER's IP address: ")
    # PEER_SEND_PORT = int(input("Enter your send port (should be the same as second's peer listening port): "))
    # PEER_LISTEN_PORT = int(input("Enter your listening port (should be the same as second's peer sending port): "))
    #
    # if MY_IP < PEERS_IP: start_handshake = True
    # elif MY_IP==PEERS_IP:
    #     if PEER_LISTEN_PORT > PEER_SEND_PORT:
    #         start_handshake = True
    #     else:
    #         start_handshake = False
    # else: start_handshake = False

    MY_IP = "localhost"
    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 8000
        PEER_SEND_PORT = 7000
        start_handshake = True
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 7000
        PEER_SEND_PORT = 8000
        start_handshake = False

    peer = Peer(MY_IP, PEERS_IP, PEER_LISTEN_PORT, PEER_SEND_PORT, start_handshake)
    if not peer.handshake():
        print("Failed to establish connection exiting.")
        exit()
    else:
        print(f"#Starting data exchange\n")

    receive_thread = threading.Thread(target=peer.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    peer.send_message()