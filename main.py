import random
import socket
import threading
import time

import crcmod
from collections import deque

from Packet import Packet
from Flags import Flags
from Prints import Prints


FRAGMENT_SIZE = 2

def calc_checksum(message):
    crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000) #0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
    checksum = crc16_func(message.encode('utf-8'))
    return checksum

def rebuild_fragments(fragments):
    full_message = ""
    expeted_id = fragments[0].identification

    for fragment in fragments:
        if fragment.checksum != calc_checksum(fragment.message):
            print("Error: Checksum mismatch in fragment.")
            return None

        if fragment.identification != expeted_id:
            print("Error: Identification mismatch in fragment.")

        full_message += fragment.message
        expeted_id += 1
    return full_message

class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        self.id = (my_ip, listen_port)
        self.send_port = send_port
        self.peer_address = (target_ip, self.send_port)
        self.seq_num = random.randint(0, 1000)
        self.ack_num = 0
        # sockets
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # threading variables
        self.queue_lock = threading.Lock()
        self.message_queue = deque()
        self.successful_delivery = threading.Event()
        self.successful_kal_delivery = threading.Event()
        #quit variables
        self.freeze_loops = False
        self.kill_communication = False

    def handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        # Set timeout for waiting on incoming packets
        self.receiving_socket.settimeout(retry_interval)

        while retries < max_retries:
            try:
                try:
                    data, addr = self.receiving_socket.recvfrom(1024)
                    received_packet = Packet.deconcatenate(data)

                    if received_packet.flags == Flags.SYN:  # Received SYN from the other peer
                        print(f"\n< Received handshake SYN <")
                        self.ack_num = received_packet.seq_num + 1
                        SYN_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.SYN_ACK)
                        self.send_socket.sendto(SYN_ACK_packet.concatenate(), self.peer_address)
                        print(f"> Sent handshake SYN/ACK >")
                        self.seq_num += 1

                    elif received_packet.flags == Flags.SYN_ACK:  # Received SYN/ACK in response to our SYN
                        print(f"< Received handshake SYN/ACK <")
                        self.seq_num += 1
                        ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.ACK)
                        self.send_socket.sendto(ACK_packet.concatenate(), self.peer_address)
                        self.ack_num = received_packet.seq_num + 1
                        print(f"> Sent handshake ACK >")
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                    elif received_packet.flags == Flags.ACK:  # Received final ACK confirming the handshake
                        print(f"< Received handshake ACK <")
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                except socket.timeout:
                    # If nothing was received, initiate the handshake by sending SYN
                    if retries == 0:
                        SYN_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.SYN)
                        self.send_socket.sendto(SYN_packet.concatenate(), self.peer_address)
                        print(f"\n> Sent handshake SYN (attempt {retries + 1}) >")

                retries += 1

            except socket.timeout:
                print(f"Retrying... (attempt {retries + 1})")

        print(f"Handshake timeout after {max_retries} retries")
        self.receiving_socket.close()
        return False

    def receive_messages(self):
        fragments = []
        while not self.freeze_loops:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)
                packet = Packet.deconcatenate(data)
                ############## TER ###################################
                if packet.flags == Flags.TER:
                    Prints.start_termination()
                    self.freeze_loops = True
                    if self.answer_terminate_connection():
                        self.receiving_socket.close()
                        self.kill_communication = True
                    return
                ############## ACK ###################################
                elif packet.flags == Flags.ACK:
                    self.successful_delivery.set()
                ############## KAL ###################################
                elif packet.flags == Flags.KAL:
                    self.enqueue_messages("", Flags.KAL_ACK, True)
                    self.successful_delivery.set()
                elif packet.flags == Flags.KAL_ACK:
                    self.successful_kal_delivery.set()
                ############## FRAGMENTED Message #####################
                elif packet.flags == Flags.FRP:
                    fragments.append(packet)
                elif packet.flags == Flags.FRP_ACK:
                    fragments.append(packet)
                    Prints.received_joined_fragments(rebuild_fragments(fragments))
                    fragments = []


                ############## Regular Message #######################
                elif packet.seq_num == self.ack_num:
                    if packet.checksum != calc_checksum(packet.message):
                        Prints.checksum_err()
                        continue

                    self.ack_num += len(packet.message)  # add length of message to my ack_num
                    ack_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.ACK)
                    self.send_socket.sendto(ack_packet.concatenate(), self.peer_address)

                    if packet.flags != Flags.ACK:
                        Prints.received_package(packet)
                        Prints.info_menu()

                else:
                    Prints.out_of_order_err()

            except socket.timeout:
                continue

    def enqueue_messages(self, data, flags_to_send, push_to_front=False):
        # if message is smaller than fragment limit, push it to the queue immediately without fragment
        if len(data) <= FRAGMENT_SIZE:
            packet = Packet(data, seq_num=self.seq_num, ack_num=self.ack_num, checksum=calc_checksum(data), flags=flags_to_send)
            if push_to_front:
                self.message_queue.appendleft(packet)
            else:
                self.message_queue.append(packet)
        else: # split data to be sent into multiple fragments if needed
            fragments = [data[i:i + FRAGMENT_SIZE] for i in range(0, len(data), FRAGMENT_SIZE)]
            with self.queue_lock:
                for i, fragment in enumerate(fragments):
                    if i == len(fragments) - 1: #if it is last fragment, mark it with FRP/ACK
                        fragment_flag = Flags.FRP_ACK
                    else:
                        fragment_flag = Flags.FRP

                    packet = Packet(fragment, seq_num=self.seq_num, ack_num=self.ack_num, identification=i,
                                    checksum=calc_checksum(fragment), flags=fragment_flag)

                    self.message_queue.append(packet)


    def send_from_queue(self):
        while not self.freeze_loops:
            if not self.message_queue:
                continue

            packet = self.message_queue[0]
            packet.seq_num = self.seq_num
            self.send_socket.sendto(packet.concatenate(), self.peer_address)

            if packet.flags == Flags.NONE:
                Prints.send_packet(packet)
            if packet.flags != Flags.NONE:
                with self.queue_lock:
                    self.message_queue.popleft()  # Remove the message from the queue
                    continue

            self.successful_delivery.clear() #?

            if self.successful_delivery.wait(timeout=5): # or self.successful_kal_delivery.wait(timeout=5):
                if packet.flags == Flags.NONE:
                    self.seq_num += len(packet.message)  # Update seq_num on success
                    print("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
                with self.queue_lock:
                    self.message_queue.popleft()  # Remove the sended message from the queue
            else:
                # Retry up to max_retries if no acknowledgment is received
                retries = 0
                max_retries = 5
                while retries < max_retries and not self.successful_delivery.is_set():
                    print(f"Retrying message '{packet.message}'... (Attempt {retries + 1})")
                    self.send_socket.sendto(packet.concatenate(), self.peer_address)
                    retries += 1

                    # Remove packet after maximum retries without acknowledgment
                    if retries == max_retries:
                        with self.queue_lock:
                            self.message_queue.popleft()
                        print(f"Failed to deliver message '{packet.message}' after {max_retries} attempts")

    def start_keep_alive(self):
        kal_delivery_error = 0
        delay = random.uniform(3, 10)
        time.sleep(delay)

        while not self.freeze_loops:
            self.successful_kal_delivery.clear()
            self.enqueue_messages("", Flags.KAL, True)

            delivery = self.successful_kal_delivery.wait(timeout=3)

            if delivery:
                if kal_delivery_error > 0:
                    print("✓ Peer is back online, communication continues ✓")
                kal_delivery_error = 0

                # print(f"✓ other peer still alive ✓ {kal_delivery_error}")
            elif not delivery:
                kal_delivery_error += 1
                print(f"X Didn't receive KAL/ACK from other peer. (other peer disconnected?) X")

            if kal_delivery_error == 3:
                print(f"\n!! NOT RECEIVED KEEP ALIVE FROM OTHER PEER FOR {kal_delivery_error} TIMES, EXITING CODE")
                print("(enter anything to proceed)")
                self.freeze_loops = True
                self.kill_communication = True
                return

            time.sleep(4) #for 4 seconds, do nothing

        return

    def start_terminate_connection(self):
        print("#starting termination process")
        retry_interval = 2
        max_retries = 15
        retries = 0

        while retries < max_retries:
            try:
                # send TER
                TER_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.TER) # SYN
                self.send_socket.sendto(TER_packet.concatenate(), self.peer_address)
                print(f"\n1. SENT termination (attempt {retries + 1})")
                retries += 1

                # Expect TER/ACK
                self.receiving_socket.settimeout(retry_interval)  # if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1024)

                TER_ACK_packet = Packet.deconcatenate(data)

                if TER_ACK_packet.flags == Flags.TER_ACK:  # if TER/ACK received
                    print(f"2. RECEIVED termination TER/ACK")
                    self.seq_num += 1  # sent one phantom byte
                    self.ack_num = TER_ACK_packet.seq_num + 1  # Update ACK number to one more than received seq num
                    ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.ACK)  # ACK

                    self.send_socket.sendto(ACK_packet.concatenate(), self.peer_address)
                    print(f"3. SENT termination ACK")
                    self.seq_num += 1  # after succesfull handshake, "I am waiting for this package"

                    self.receiving_socket.close()
                    self.kill_communication = True
                    print(f"\n## Termination successful, connection ended")
                    return



            except socket.timeout:
                print(f"retrying termination... (attempt {retries + 1})")
    def answer_terminate_connection(self):
        TER_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.TER_ACK)  # send SYN-ACK
        self.send_socket.sendto(TER_ACK_packet.concatenate(), self.peer_address)
        print(f"2. Sent termination TER/ACK")

        while True:
            data, addr = self.receiving_socket.recvfrom(1024)  # recieve ACK
            ACK_packet = Packet.deconcatenate(data)

            if ACK_packet.flags == Flags.ACK:  # if ACK received
                print(f"3. Received termination ACK")
                print(f"\n##Termination successful, connection ended")
                self.kill_communication = True
                # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                return True

    def show_menu(self):
        while True:
            choice = Prints.menu()
            if self.kill_communication:
                return

            if choice == 'm':
                print("##############################")
                message = input("Enter message: ").strip()
                print("##############################")
                self.enqueue_messages(message, Flags.NONE)
            elif choice == 'f':
                print("not ready yet")
            elif choice == '!q' or '!quit':
                self.freeze_loops = True
                self.start_terminate_connection()
                break
            else:
                print("Invalid choice. Please try again.")

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
    if not peer.handshake():
        print("Failed to establish connection exiting.")
        exit()
    else:
        print(f"#  Starting data exchange\n")

    send_thread = threading.Thread(target=peer.send_from_queue)
    send_thread.daemon = True #?
    send_thread.start()

    receive_thread = threading.Thread(target=peer.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    # if whos_this == "1":
    keep_alive_thread = threading.Thread(target=peer.start_keep_alive)
    keep_alive_thread.daemon = True
    keep_alive_thread.start()

    peer.show_menu()