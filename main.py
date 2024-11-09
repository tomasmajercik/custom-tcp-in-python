import random
import socket
import threading
import time
import crcmod
from collections import deque

from Packet import Packet

#flags:
ACK = 0b0010
NACK = 0b1101
NONE = 0b0000

SYN = 0b0001
SYN_ACK = 0b0011

CFL = 0b0100
FRP = 0b1000
KAL = 0b1001
KAL_ACK = 0b1011

TER = 0b1100
TER_ACK = 0b1110


def calc_checksum(message):
    crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000) #0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
    checksum = crc16_func(message.encode('utf-8'))
    return checksum

class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        self.id = (my_ip, listen_port)
        self.send_port = send_port
        self.peer_address = (target_ip, self.send_port)

        # Receiving socket
        self.receiving_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.receiving_socket.bind(self.id)

        # Sending socket (no need to bind, just used for sending)
        self.send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.seq_num = random.randint(0, 1000)
        self.ack_num = 0

        self.queue_lock = threading.Lock()
        self.message_queue = deque()

        self.successful_delivery = threading.Event()
        self.successful_kal_delivery = threading.Event()

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

                    if received_packet.flags == SYN:  # Received SYN from the other peer
                        print(f"\nReceived handshake SYN")
                        self.ack_num = received_packet.seq_num + 1
                        SYN_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=SYN_ACK)
                        self.send_socket.sendto(SYN_ACK_packet.concatenate(), self.peer_address)
                        print(f"Sent handshake SYN/ACK")
                        self.seq_num += 1

                    elif received_packet.flags == SYN_ACK:  # Received SYN/ACK in response to our SYN
                        print(f"Received handshake SYN/ACK")
                        self.seq_num += 1
                        ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=ACK)
                        self.send_socket.sendto(ACK_packet.concatenate(), self.peer_address)
                        self.ack_num = received_packet.seq_num + 1
                        print(f"Sent handshake ACK")
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                    elif received_packet.flags == ACK:  # Received final ACK confirming the handshake
                        print(f"Received handshake ACK")
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                except socket.timeout:
                    # If nothing was received, initiate the handshake by sending SYN
                    if retries == 0:
                        SYN_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=SYN)
                        self.send_socket.sendto(SYN_packet.concatenate(), self.peer_address)
                        print(f"\nSent handshake SYN (attempt {retries + 1})")

                retries += 1

            except socket.timeout:
                print(f"Retrying... (attempt {retries + 1})")

        print(f"Handshake timeout after {max_retries} retries")
        self.receiving_socket.close()
        return False

    def receive_messages(self):
        while not self.freeze_loops:
            try:
                data, addr = self.receiving_socket.recvfrom(1024)
                packet = Packet.deconcatenate(data)
                ############## TER ###################################
                if packet.flags == TER:
                    print(f"\n\n #Another peer terminates the connection!")
                    print(f"1. RECEIVED termination TER")
                    self.freeze_loops = True
                    if self.answer_terminate_connection():
                        self.receiving_socket.close()
                        self.kill_communication = True
                    return
                ############## ACK ###################################
                elif packet.flags == ACK:
                    self.successful_delivery.set()
                ############## KAL ###################################
                elif packet.flags == KAL:
                    self.enqueue_messages("KAL/ACK", KAL_ACK, True)
                    self.successful_delivery.set()
                elif packet.flags == KAL_ACK:
                    self.successful_kal_delivery.set()

                ############## Message ###############################
                elif packet.seq_num == self.ack_num:
                    if packet.checksum != calc_checksum(packet.message):
                        print("! Checksum does not match !")
                        continue

                    self.ack_num += len(packet.message)  # add length of message to my ack_num
                    ack_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=ACK)
                    self.send_socket.sendto(ack_packet.concatenate(), self.peer_address)

                    if packet.flags != ACK:
                        print(f"\n__________________________________________")
                        print(f"Received << {packet.seq_num}|{packet.ack_num}|{packet.message} ")
                        print(f"____________________________________________\n")

                else:
                    print("!!Out of order packet received, ignoring!!")
                    # Send an acknowledgment for the last valid packet
                    # ask for lost package?

            except socket.timeout:
                continue

    def enqueue_messages(self, message, flags_to_send, push_to_front=False):
        with self.queue_lock:
            packet = Packet(message, seq_num=self.seq_num, ack_num=self.ack_num, checksum=calc_checksum(message), flags=flags_to_send)
            if push_to_front:
                self.message_queue.appendleft(packet)
            else:
                self.message_queue.append(packet)
    def send_from_queue(self):
        while not self.freeze_loops:
            if not self.message_queue:
                continue

            packet = self.message_queue[0]
            self.send_socket.sendto(packet.concatenate(), self.peer_address)
            if packet.flags == NONE: print(f"\n>>>> \nSent: {packet.seq_num}|{packet.ack_num}|{packet.message}")
            if packet.flags != NONE:
                with self.queue_lock:
                    self.message_queue.popleft()  # Remove the message from the queue
                    continue


            self.successful_delivery.clear() #?

            if self.successful_delivery.wait(timeout=5): # or self.successful_kal_delivery.wait(timeout=5):
                if packet.flags == NONE:
                    self.seq_num += len(packet.message)  # Update seq_num on success
                    print("<<<<")
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

        while not self.kill_communication:
            self.successful_kal_delivery.clear()
            self.enqueue_messages("(kal)", KAL, True)

            delivery = self.successful_kal_delivery.wait(timeout=3)

            if delivery:
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

            time.sleep(4) #for 5 seconds, do nothing

        return

    def start_terminate_connection(self):
        print("#starting termination process")
        retry_interval = 2
        max_retries = 15
        retries = 0

        while retries < max_retries:
            try:
                # send TER
                TER_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=TER)  # SYN
                self.send_socket.sendto(TER_packet.concatenate(), self.peer_address)
                print(f"\n1. SENT termination (attempt {retries + 1})")
                retries += 1

                # Expect TER/ACK
                self.receiving_socket.settimeout(retry_interval)  # if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1024)

                TER_ACK_packet = Packet.deconcatenate(data)

                if TER_ACK_packet.flags == TER_ACK:  # if TER/ACK received
                    print(f"2. RECEIVED termination TER/ACK")
                    self.seq_num += 1  # sent one phantom byte
                    self.ack_num = TER_ACK_packet.seq_num + 1  # Update ACK number to one more than received seq num
                    ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=ACK)  # ACK

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
        TER_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=TER_ACK)  # send SYN-ACK
        self.send_socket.sendto(TER_ACK_packet.concatenate(), self.peer_address)
        print(f"2. Sent termination TER/ACK")

        while True:
            data, addr = self.receiving_socket.recvfrom(1024)  # recieve ACK
            ACK_packet = Packet.deconcatenate(data)

            if ACK_packet.flags == ACK:  # if ACK received
                print(f"3. Received termination ACK")
                print(f"\n##Termination successful, connection ended")
                self.kill_communication = True
                # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                return True



    def show_menu(self):
        while True:
            print("\nMENU:")
            #print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
            print("'m' for message | 'f' for file | '!q / !quit' for quit")


            choice = input("Choose an option: ").strip()

            if self.kill_communication:
                return

            if choice == 'm':
                message = input("Enter message: ").strip()
                self.enqueue_messages(message, NONE)
            # elif choice == 'sml':
            #     message = input("Enter message: ").strip()
            #     self.send_message(message, True)
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
        print(f"#Starting data exchange\n")

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