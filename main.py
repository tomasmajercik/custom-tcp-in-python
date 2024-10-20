import queue
import random
import socket
import threading

from Packet import Packet

#flags:
SYN = 0b0000
ACK = 0b0000
SYN_ACK = 0b0000
CFL = 0b0000
FRP = 0b0000
KAL = 0b0000
NACK = 0b0000
TER = 0b0000

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

        # Condition to synchronize sender and receiver
        self.condition = threading.Condition()

        # Message queue for sending
        self.send_queue = queue.Queue()
        self.ack_event = threading.Event()

    def handshake(self):
        if self.start_handshake: return self.initiate_handshake()
        elif not self.start_handshake: return self.expect_handshake()

    def initiate_handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        #! dohodnut checksum

        while retries < max_retries:
            try:
                # send SYN
                SYN_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b001)  # SYN
                self.send_socket.sendto(SYN_packet.concatenate().encode(), self.peer_address)
                print(f"\n1. SENT handshake invite: {SYN_packet.concatenate()} (attempt {retries + 1})")
                print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")
                retries += 1

                # Expect SYN/ACK
                self.receiving_socket.settimeout(retry_interval) #if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1024)

                SYN_ACK_packet = Packet.deconcatenate(data.decode())

                if SYN_ACK_packet.flags == 0b011:  # if SYN/ACK received
                    print(f"2. RECEIVED handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")
                    print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")
                    self.seq_num += 1 #sent one phantom byte
                    self.ack_num = SYN_ACK_packet.seq_num + 1  # Update ACK number to one more than received seq num
                    ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b010)  # ACK

                    self.send_socket.sendto(ACK_packet.concatenate().encode(), self.peer_address)
                    print(f"3. SENT handshake ACK: {ACK_packet.concatenate()}")
                    print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")
                    self.seq_num += 1 #after succesfull handshake, "I am waiting for this package"

                    print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                    return True

            except socket.timeout:
                print(f"retrying... (attempt {retries + 1})")
                # continue in sending SYN packages

        print(f"Handshake timeout after {max_retries} retries")
        self.receiving_socket.close()
        self.receiving_socket.settimeout(None)
        return False
    def expect_handshake(self):
        max_time_duration = 30
        self.receiving_socket.settimeout(max_time_duration)
        #! dohodnut checksum
        try:
            while True:
                data, addr = self.receiving_socket.recvfrom(1024)
                SYN_packet = Packet.deconcatenate(data.decode())
                if SYN_packet.flags == 0b001:  # if received SYN
                    print(f"\n1. Received handshake SYN: {SYN_packet.concatenate()}")
                    print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")
                    self.ack_num = SYN_packet.seq_num + 1

                    SYN_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b011)  # send SYN-ACK
                    self.send_socket.sendto(SYN_ACK_packet.concatenate().encode(), self.peer_address)
                    print(f"2. Sent handshake SYN/ACK: {SYN_ACK_packet.concatenate()}")
                    print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")

                    data, addr = self.receiving_socket.recvfrom(1024) #recieve ACK
                    ACK_packet = Packet.deconcatenate(data.decode())

                    if ACK_packet.flags == 0b010:  # if ACK received
                        print(f"3. Received handshake ACK: {ACK_packet.concatenate()}")
                        self.seq_num += 1
                        self.ack_num += 1
                        print(f"\n##Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        print(f"seq: {self.seq_num} ||| ack: {self.ack_num}")
                        # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                        self.receiving_socket.settimeout(None)
                        return True
        except socket.timeout:
            print(f"No handshake for {max_time_duration} seconds, exiting the code")
            self.receiving_socket.settimeout(None)
            return False


    def receive_messages(self):
        while True:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)
                packet = Packet.deconcatenate(data.decode())

                if packet.seq_num == self.ack_num:
                    if packet.flags != 0b010:
                        print(f"\nReceived << {packet.seq_num}|{packet.ack_num} said: \"{packet.message}\"")

                    self.ack_num += len(packet.get_message()) or 1
                    ack_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=0b010)
                    self.send_socket.sendto(ack_packet.concatenate().encode(), self.peer_address)

                    self.ack_event.set()  # Acknowledgment event is set (notify sender thread)
                else:
                    print("Out of order packet received, ignoring")
            except socket.timeout:
                continue

            print("\nMENU:")
            print("'m' for message | 'f' for file | '!quit' for quit")
            print(f"Choose an option: ")

    def send_message(self, message, simulate_package_loss):
        packet = Packet(message, seq_num=self.seq_num, ack_num=self.ack_num, flags=0b000)
        self.send_queue.put((packet, simulate_package_loss))

    def process_send_queue(self):
        while True:
            packet, simulate_package_loss = self.send_queue.get()

            if simulate_package_loss:
                print("~simulating this packet was lost~")
                simulate_package_loss = False
                continue

            print(f"Sent >> {packet.seq_num}|{packet.ack_num} msg: \"{packet.message}\"")
            self.send_socket.sendto(packet.concatenate().encode(), self.peer_address)

            self.ack_event.clear()  # Clear the acknowledgment event
            self.ack_event.wait(timeout=5)  # Wait for acknowledgment for 5 seconds

            if self.ack_event.is_set():
                print("<Acknowledgment successful>")
                self.seq_num += len(packet.message) or 1
            else:
                print("Acknowledgment timeout, resending packet")
                self.send_queue.put((packet, False))  # Requeue for retry

    def show_menu(self):
        while True:
            print("\nMENU:")
            print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
            choice = input("Choose an option: ").strip()

            if choice == 'm':
                message = input("Enter message: ").strip()
                self.send_message(message, False)
            elif choice == 'sml':
                message = input("Enter message: ").strip()
                self.send_message(message, True)
            elif choice == 'f':
                print("not ready yet")
            elif choice == '!quit':
                print("Exiting...")
                self.receiving_socket.close()
                break
            else:
                print("Invalid choice. Please try again.")


if __name__ == '__main__':

    # MY_IP = "192.168.0.1"
    MY_IP = "localhost"

    # PEERS_IP = input("Enter PEER's IP address: ")
    # PEER_SEND_PORT = int(input("Enter your send port (should be the same as second's peer listening port): "))
    # PEER_LISTEN_PORT = int(input("Enter your listening port (should be the same as second's peer sending port): "))
    # if MY_IP < PEERS_IP: start_handshake = True
    # else: start_handshake = False

    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        # PEERS_IP = "192.168.0.2"
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 5000
        PEER_SEND_PORT = 4000
        start_handshake = True
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 4000
        PEER_SEND_PORT = 5000
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

    send_thread = threading.Thread(target=peer.process_send_queue)
    send_thread.daemon = True
    send_thread.start()

    peer.show_menu()



#need to be done:
    # dohodnut ten fragment v handshaku - dalsia flaga
    # when !quit -> terminate both sides - dalsia flaga
    # keep alive -> ak sa jeden odpoji, odpoji sa aj dryhy alebo posielam handshake - dalsia flaga?
    # ked poslem naraz package z jedneho na druhy peer tak sa to uplne doserie, preco....?

    # ak je mismatch ack musim si poprosit ten package znova... should not happen due to stop&wait???

    # upratat konzolu nech je tam vzdy to ze vyber si co chces poslat aj !quit aj vsetko
