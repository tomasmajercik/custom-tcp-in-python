import socket
import random
import threading

import crcmod
from collections import deque

from Packet import Packet
from Prints import Prints
from Flags import Flags

FRAGMENT_SIZE = 50
MAX_FRAGMENT_SIZE = 1457 # Ethernet-IP Header-UDP Header-Custom Protocol Header = 1500−20−8-15 = 1457


def calc_checksum(message):
    if isinstance(message, str):
        message = message.encode()  # Convert to bytes if it's a string
    crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000) #0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
    checksum = crc16_func(message)
    return checksum


class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        #queue
        self.data_queue = deque()
        # routing variables
        self.id = (my_ip, listen_port)
        self.peer_address = (target_ip, send_port)
        # syn/ack variables
        self.seq_num = random.randint(0, 1000)
        self.ack_num = 0
        # sockets
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # threading variables
        self.received_ack = threading.Event()

#### HANDSHAKE #########################################################################################################
    def handshake(self):
        max_retries = 15
        retries = 0

        # Set timeout for waiting on incoming packets
        self.receiving_socket.settimeout(2.0)

        while retries < max_retries:
            try:
                try:
                    data, addr = self.receiving_socket.recvfrom(1500)
                    received_packet = Packet.deconcatenate(data)

                    if received_packet.flags == Flags.SYN:  # Received SYN from the other peer
                        print(f"\n< Received handshake SYN <")
                        self.ack_num = received_packet.seq_num + 1
                        SYN_ACK_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.SYN_ACK)
                        self.send_socket.sendto(SYN_ACK_packet.concatenate(), self.peer_address)
                        print(f"> Sent handshake SYN/ACK >")
                        self.seq_num += 1

                    elif received_packet.flags == Flags.SYN_ACK:  # Received SYN/ACK in response to our SYN
                        print(f"< Received handshake SYN/ACK <")
                        self.seq_num += 1
                        ACK_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.ACK)
                        self.send_socket.sendto(ACK_packet.concatenate(), self.peer_address)
                        self.ack_num = received_packet.seq_num + 1
                        print(f"> Sent handshake ACK >")
                        print(
                            f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                    elif received_packet.flags == Flags.ACK:  # Received final ACK confirming the handshake
                        print(f"< Received handshake ACK <")
                        print(
                            f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                except socket.timeout:
                    # If nothing was received, initiate the handshake by sending SYN
                    if retries == 0:
                        SYN_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.SYN)
                        self.send_socket.sendto(SYN_packet.concatenate(), self.peer_address)
                        print(f"\n> Sent handshake SYN (attempt {retries + 1}) >")

                retries += 1

            except socket.timeout:
                print(f"Retrying... (attempt {retries + 1})")

        print(f"Handshake timeout after {max_retries} retries")
        self.receiving_socket.close()
        return False

#### SENDING AND RECEIVING #############################################################################################
    def send_data_from_queue(self): # is in send_thread thread
        while True:
            if not self.data_queue: # if queue is empty, do nothing
                continue

            ######## prepare the package #######################
            packet_to_send = self.data_queue[0] # take first from queue
            packet_to_send.seq_num = self.seq_num # set current seq
            packet_to_send.ack_num = self.ack_num # set current ack

            ####### STOP & WAIT ########################################################################################
            while True:
                self.received_ack.clear()

                ######## send the packet ##########################
                self.send_socket.sendto(packet_to_send.concatenate(), self.peer_address)

                #### flags that don't have to be acknowledged ###
                if packet_to_send.flags in {Flags.ACK}:
                    self.data_queue.popleft()
                    break

                # Wait for ACK or timeout
                ack_received = self.received_ack.wait(timeout=5.0)

                if ack_received:
                    # print("Ack received")
                    self.seq_num += len(packet_to_send.data)
                    self.data_queue.popleft()
                    break
                else:
                    print("\n!ACK not received, resending packet! \n")




        return
    def receive_data(self): # is NOT in thread so the program can terminate later
        while True:
            try:
                # set timeout for waiting
                self.receiving_socket.settimeout(2.0)

                # receive data
                packet_data, addr = self.receiving_socket.recvfrom(1500)
                rec_packet = Packet.deconcatenate(packet_data)

                ##### rec. ACK #########################################################################################
                if rec_packet.flags == Flags.ACK: # and rec_packet.ack_num == self.seq_num + 1: - if want to check seq/ack
                    self.received_ack.set()
                    self.ack_num = rec_packet.seq_num + 1
                    continue

                ####### Ordinary messages ##############################################################################
                if rec_packet.flags == Flags.NONE: # is an ordinary messaga
                    if rec_packet.checksum != calc_checksum(rec_packet.data): # calculate checksum
                        print("checksum does not match - message corrupted")
                        continue

                    print(f"\n\n<<<<<<\nRECEIVED data: {rec_packet.data.decode()} \n<<<<<< \n")
                    #### send ACK to signal data were received correctly
                    self.ack_num = rec_packet.seq_num + len(rec_packet.data)
                    self.enqueue_message("ack", flags_to_send=Flags.ACK, push_to_front=True) # send ack
                    continue
                ########################################################################################################


            except socket.timeout:
                continue

#### ENQUEING ##########################################################################################################
    def enqueue_message(self, message="", flags_to_send=Flags.NONE, push_to_front=False):
        if len(message) < FRAGMENT_SIZE:
            packet = Packet(identification=0, checksum=calc_checksum(message), flags=flags_to_send, data=message)
            if push_to_front: self.data_queue.appendleft(packet)
            elif not push_to_front: self.data_queue.append(packet)
        return

#### PROGRAM CONTROL ###################################################################################################
    def manage_user_input(self): # is in input_thread thread
        while True:
            Prints.info_menu() # show menu
            choice = input("Enter your choice: ")

            if choice == "m": #message
                print("\n##############")
                message = input("Enter message: ")
                print("##############\n")
                self.enqueue_message(message)
                continue

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
    else:
        PEERS_IP = "localhost"
        PEER_LISTEN_PORT = 7000
        PEER_SEND_PORT = 8000

    peer = Peer(MY_IP, PEERS_IP, PEER_LISTEN_PORT, PEER_SEND_PORT)
#### HANDSHAKE #########################################################################################################
    if not peer.handshake():
        print("Failed to establish connection exiting.")
        exit()
    else:
        print(f"#  Starting data exchange\n")

#### THREADS ###########################################################################################################
    input_thread = threading.Thread(target=peer.manage_user_input)
    input_thread.daemon = True
    input_thread.start()

    send_thread = threading.Thread(target=peer.send_data_from_queue)
    send_thread.daemon = True
    send_thread.start()

    peer.receive_data()















