import os
import random
import socket
import threading

import crcmod
from collections import deque

import Prints
from Packet import Packet
from Flags import Flags
from Prints import *


# FRAGMENT_SIZE = 100
FRAGMENT_SIZE = 1457
MAX_FRAGMENT_SIZE = 1457 # Ethernet-IP Header-UDP Header-Custom Protocol Header = 1500−20−8-15 = 1457
#este path aby existovala treba zistit

def calc_checksum(message):
    if isinstance(message, str):
        message = message.encode()  # Convert to bytes if it's a string
    crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, xorOut=0x0000) #0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
    checksum = crc16_func(message)
    return checksum


def rebuild_fragments(fragments):
    full_message = ""
    expeted_id = fragments[0].identification

    for fragment in fragments:
        if fragment.checksum != calc_checksum(fragment.message.encode()):
            print("Error: Checksum mismatch in fragment.")
            return None

        if fragment.identification != expeted_id:
            print("Error: Identification mismatch in fragment.")

        full_message += fragment.message
        expeted_id += 1
    return full_message, expeted_id





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
        self.fragments_sending = threading.Event()
        self.is_sending_data = threading.Event()
        self.is_receiving_data = threading.Event()
        #quit variables
        self.freeze_loops = False
        self.kill_communication = False

    def send_ack(self, packet):
        self.ack_num += len(packet.message)  # add length of message to my ack_num
        ack_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=Flags.ACK)
        self.send_socket.sendto(ack_packet.concatenate(), self.peer_address)


    def handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        # Set timeout for waiting on incoming packets
        self.receiving_socket.settimeout(retry_interval)

        while retries < max_retries:
            try:
                try:
                    data, addr = self.receiving_socket.recvfrom(1500)
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

    def merge_file_fragments(self, fragments, file_metadata):

        print("All data received - press ENTER to proceed")
        while True:
            save_path = input("Enter desired path to save file: ")

            if os.path.exists(save_path):
                print("~~ saving file, please wait ~~")
                break  # Exit the loop if the path exists
            else:
                print("File path does not exist. Please try again.")

        # save_path = "/home/tomasmajercik/Desktop/peer2/"
        merged_file = b''
        for fragment in fragments:
            # Check if the fragment's message is in bytes or string, and handle accordingly
            if isinstance(fragment.message, str):
                merged_file += fragment.message.encode('utf-8')  # Encode string to bytes
            else:
                merged_file += fragment.message  # Assume it's already bytes

        file_name, file_size, num_fragments = file_metadata.split(":")
        file_path = os.path.join(save_path, file_name)

        with open(file_path, 'wb') as f:
            f.write(merged_file)

        print(f"File \"{file_name}\" saved to: {file_path}")

        self.fragments_sending.clear()
        return

    def receive_messages(self):
        global FRAGMENT_SIZE
        fragments = []
        file_to_receive_metadata = ""
        fragment_count_to_receive = 100

        while not self.freeze_loops:
            try:
                data, addr = self.receiving_socket.recvfrom(1500)
                self.is_receiving_data.set()
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
                    # print("RECEIVED KALLLLL")
                    self.enqueue_messages("", Flags.KAL_ACK, True)
                    self.successful_delivery.set()
                elif packet.flags == Flags.KAL_ACK:
                    self.successful_kal_delivery.set()
                ############## FRAGMENTED Message #####################
                elif packet.flags == Flags.FRP:
                    fragments.append(packet)
                    self.send_ack(packet)
                elif packet.flags == Flags.FRP_ACK:
                    self.send_ack(packet)
                    fragments.append(packet)
                    message, number_of_fragments = rebuild_fragments(fragments)
                    Prints.received_joined_fragments(message, number_of_fragments)
                    fragments = []


                ############## FILE ##################################
                elif packet.flags == Flags.F_INFO:
                    self.fragments_sending.set()
                    if packet.checksum != calc_checksum(packet.message.encode()):
                        Prints.checksum_err()
                        continue

                    self.send_ack(packet)

                    fragments = []
                    file_to_receive_metadata = packet.message
                    print(f"\n< Received file transfer request for '{file_to_receive_metadata}' >")
                    Prints.print_receive_file()
                    fragment_count_to_receive = packet.message.split(":")[2]
                elif packet.flags == Flags.FILE:
                    if packet.checksum != calc_checksum(packet.message):
                        print("CORRUPETED HERE")
                    fragments.append(packet)
                    print(f"Received fragment - completed {(packet.identification * 100 / int(fragment_count_to_receive)):.2f}%")
                    self.send_ack(packet)
                elif packet.flags == Flags.LAST_FILE:
                    fragments.append(packet)
                    self.send_ack(packet)
                    # start thread to merge fragments together but do not block main program
                    merge_file_fragments_thread = threading.Thread(target=self.merge_file_fragments, args=(fragments, file_to_receive_metadata))
                    merge_file_fragments_thread.daemon = True
                    merge_file_fragments_thread.start()
                    fragments = []

                ############## CFL ###################################
                elif packet.flags == Flags.CFL:
                    old_limit = FRAGMENT_SIZE
                    FRAGMENT_SIZE = int(packet.message)
                    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    print(f"Other peer has just changed fragmentation limit from {old_limit} to {FRAGMENT_SIZE}")
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                ############## Regular Message #######################
                elif packet.seq_num == self.ack_num:
                    if packet.checksum != calc_checksum(packet.message.encode()):
                        Prints.checksum_err()
                        continue

                    self.send_ack(packet)

                    if packet.flags != Flags.ACK:
                        Prints.received_package(packet)
                        Prints.info_menu()

                else:
                    Prints.out_of_order_err()

            except socket.timeout:
                continue

    def enqueue_file(self, file_path):
        print("Wait, file enqueing is in progress")

        file_name = file_path.split("/")[-1]  # Extract file name from path
        file_size = os.path.getsize(file_path)
        num_fragments = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE  # Calculate the total number of fragments

        # 1. Prepare metadata packet with file name, file size, and fragment count
        file_metadata = f"{file_name}:{file_size}:{num_fragments}"
        metadata_packet = Packet(file_metadata, self.seq_num, self.ack_num, checksum=calc_checksum(file_metadata.encode()), flags=Flags.F_INFO)
        with self.queue_lock:
            self.message_queue.append(metadata_packet)

        # 2. send file data in fragments
        with open(file_path, "rb") as f:
            for i in range(num_fragments):
                fragment = f.read(FRAGMENT_SIZE)
                if not fragment:
                    break  # End of file reached

                # If this is the last fragment, set the flag to LAST_FILE
                fragment_flag = Flags.LAST_FILE if i == num_fragments - 1 else Flags.FILE

                fragment_packet = Packet(fragment, seq_num=self.seq_num, ack_num=self.ack_num, identification=i, checksum=calc_checksum(fragment),
                                         flags=fragment_flag)
                with self.queue_lock:
                    self.message_queue.append(fragment_packet)

        print(f"File '{file_name}' enqueued with {num_fragments} fragments.")
        return

    def enqueue_messages(self, data, flags_to_send, push_to_front=False):
        # if message is smaller than fragment limit, push it to the queue immediately without fragment
        if len(data) <= FRAGMENT_SIZE:
            packet = Packet(data, seq_num=self.seq_num, ack_num=self.ack_num, checksum=calc_checksum(data.encode()), flags=flags_to_send)
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
                                    checksum=calc_checksum(fragment.encode()), flags=fragment_flag)

                    self.message_queue.append(packet)


    def send_from_queue(self):
        fragment_count_to_send = 100
        while not self.freeze_loops:
            if not self.message_queue:
                continue

            self.is_sending_data.set() # set the sending to inform keep alive that something has been sent

            packet = self.message_queue[0]
            packet.seq_num = self.seq_num
            self.send_socket.sendto(packet.concatenate(), self.peer_address)

            # if packet.flags == Flags.KAL:
            #     print(f"POSLAL SOM KAL")
            # if packet.flags == Flags.KAL_ACK:
            #     print("POSLAL SOM KAL_ACK")


            if packet.flags in {Flags.NONE, Flags.F_INFO}:
                Prints.send_packet(packet)
                if packet.flags == Flags.F_INFO:
                    fragment_count_to_send = packet.message.split(":")[2]


            # if packet.flags not in {Flags.NONE, Flags.F_INFO, Flags.FILE, Flags.LAST_FILE, Flags.FRP, Flags.FRP_ACK}: # those flags we need to wait for ack
            if packet.flags in {Flags.TER, Flags.TER_ACK, Flags.ACK, Flags.KAL, Flags.KAL_ACK, Flags.CFL}: # those which do not need ack
                with self.queue_lock:
                    self.message_queue.popleft()  # Remove the message from the queue
                    continue

            self.successful_delivery.clear() #?

            if self.successful_delivery.wait(timeout=5):
                self.seq_num += len(packet.message)  # Update seq_num on success
                if packet.flags == Flags.NONE:
                    # Prints.print_send(print_size)
                    print("<<<<")
                if packet.flags == Flags.FILE:
                    print(f"Sent fragment - completed {(packet.identification * 100 / int(fragment_count_to_send)):.2f}%")
                if packet.flags == Flags.LAST_FILE:
                    print("Sent last fragment - 100% complete")
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
            if self.is_sending_data.is_set() or self.is_receiving_data.is_set():
                self.is_sending_data.clear()
                self.is_receiving_data.clear()
                time.sleep(5)

            else: # peer send nothing and received nothing
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

                self.successful_kal_delivery.clear()
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
                self.freeze_loops = True
                print(f"\n1. SENT termination (attempt {retries + 1})")
                retries += 1

                # Expect TER/ACK
                self.receiving_socket.settimeout(retry_interval)  # if nothing received in interval, do not wait
                data, addr = self.receiving_socket.recvfrom(1500)

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
            data, addr = self.receiving_socket.recvfrom(1500)  # recieve ACK
            ACK_packet = Packet.deconcatenate(data)

            if ACK_packet.flags == Flags.ACK:  # if ACK received
                print(f"3. Received termination ACK")
                print(f"\n##Termination successful, connection ended")
                self.kill_communication = True
                # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                return True

    def show_menu(self):
        global FRAGMENT_SIZE
        while True:
            while self.fragments_sending.is_set():
                pass

            choice = Prints.menu()
            if self.kill_communication:
                return

            if choice == 'm':
                print("##############")
                message = input("Enter message: ").strip()
                print("##############")
                self.enqueue_messages(message, Flags.NONE)
            elif choice == "cfl":
                print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                print(f"Fragment size is currently set to {FRAGMENT_SIZE}")
                new_limit = input("Enter 'q' for quit   or    enter new fragment limit (or 'MAX' to set max fragments possible): ").strip()
                if new_limit == 'q':
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    continue
                if new_limit == 'MAX':
                    new_limit = str(MAX_FRAGMENT_SIZE)

                if int(new_limit) <= MAX_FRAGMENT_SIZE:
                    print(f"Changed fragmentation limit from {FRAGMENT_SIZE} to {new_limit}")
                    FRAGMENT_SIZE = int(new_limit)
                    self.enqueue_messages(new_limit, Flags.CFL, True)
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                else:
                    print(f"Can not change fragmentation limit above {MAX_FRAGMENT_SIZE}.")
            elif choice == 'f':
                file_path = input("Enter file path: ").strip()

                if not os.path.exists(file_path):
                    print("This path does not exist. Please enter valid one.")
                else:
                    self.enqueue_file(file_path)
            elif choice == '!q' or choice == '!quit':
                self.freeze_loops = True
                self.start_terminate_connection()
                break
            else:
                if not self.fragments_sending.is_set():
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

    # if who's_this == "1":
    keep_alive_thread = threading.Thread(target=peer.start_keep_alive)
    keep_alive_thread.daemon = True
    keep_alive_thread.start()

    peer.show_menu()
