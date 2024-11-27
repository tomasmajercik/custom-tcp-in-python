import hashlib
import os
import queue
import socket
import random
import threading
import time

from collections import deque

from Packet import Packet
from Functions import Functions
from Flags import Flags

FRAGMENT_SIZE = 1443
MAX_FRAGMENT_SIZE = 1443 # Ethernet-IP Header-UDP Header-Custom Protocol Header = 1500−20−8-15 = 1457
kal_delivery_error = 0

class Peer:
    def __init__(self, my_ip, target_ip, listen_port, send_port):
        #queue
        self.data_queue = deque()
        self.command_queue = queue.Queue()
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
        # ACK/NACK management
        self.received_ack = threading.Event()
        self.received_nack = threading.Event()
        self.received_NACK = threading.Event()
        # threading variables
        self.queue_lock = threading.Lock()
        self.enable_input = threading.Event()
        self.direct_input_to_main_control = threading.Event()
        self.terminate_listening = False
        # kal threading variables
        self.successful_kal_delivery = threading.Event()
        self.do_keep_alive = threading.Event()

#### Connection control ################################################################################################
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
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True
                    elif received_packet.flags == Flags.ACK:  # Received final ACK confirming the handshake
                        print(f"< Received handshake ACK <")
                        print(f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
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
    def manage_keep_alive(self):
        global kal_delivery_error
        delay = random.uniform(2, 5)
        time.sleep(delay)

        while True:
            self.do_keep_alive.wait()
            self.successful_kal_delivery.clear()
            self.enqueue_message(flags_to_send=Flags.KAL, push_to_front=True)

            start_time = time.time()
            delivery = self.successful_kal_delivery.wait(timeout=5)
            if delivery:
                if kal_delivery_error > 0:
                    print("✓ Peer is back online, communication continues ✓")
                kal_delivery_error = 0
            elif not delivery:
                kal_delivery_error += 1
                print(f"X Didn't receive KAL/ACK from other peer. (other peer disconnected?) X")

            if kal_delivery_error == 3:
                print(f"\n!! NOT RECEIVED KEEP ALIVE FROM OTHER PEER FOR {kal_delivery_error} TIMES, EXITING CODE")
                self.terminate_listening = True
                return

            elapsed_time = time.time() - start_time
            remaining_time = max(0, 5 - int(elapsed_time))
            time.sleep(remaining_time)
#### ENQUEING ##########################################################################################################
    def enqueue_file(self, file_path, simulate_error=False):
        file_name = file_path.split("/")[-1]  # Extract file name from path
        file_size = os.path.getsize(file_path)
        num_fragments = (file_size + FRAGMENT_SIZE - 1) // FRAGMENT_SIZE  # Calculate the total number of fragments

        # 1. Prepare metadata packet with file name, file size, and fragment count
        file_metadata = f"{file_name}:{file_size}:{num_fragments}"
        metadata_packet = Packet(self.seq_num, self.ack_num, checksum=Functions.calc_checksum(file_metadata),
                                 flags=Flags.F_INFO, data=file_metadata)
        self.do_keep_alive.clear()
        print(f"Sending file {file_path}")
        with self.queue_lock: self.data_queue.append(metadata_packet)

        # if simulate error is on
        corrupted_packet_id = random.randint(0, num_fragments - 1) if simulate_error else -1

        # 2. send file data in fragments
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for i in range(num_fragments):
                fragment = f.read(FRAGMENT_SIZE)
                if not fragment:
                    break  # End of file reached
                # If this is the last fragment, set the flag to LAST_FILE
                fragment_flag = Flags.FILE

                if corrupted_packet_id == i:
                    fragment_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, identification=i,
                                             checksum=0, flags=fragment_flag, data=fragment)
                else:
                    fragment_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, identification=i,
                                             checksum=Functions.calc_checksum(fragment), flags=fragment_flag, data=fragment)

                sha256.update(fragment_packet.data)
                with self.queue_lock: self.data_queue.append(fragment_packet)

        calc_hash = sha256.hexdigest()
        hash_packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, checksum=Functions.calc_checksum(calc_hash),
                                 flags=Flags.LAST_FILE, data=calc_hash)
        with self.queue_lock: self.data_queue.append(hash_packet)
        return
    def enqueue_message(self, message="", flags_to_send=Flags.NONE, push_to_front=False, simulate_error=False):
        if len(message) <= FRAGMENT_SIZE:
            packet = Packet(identification=0, checksum=Functions.calc_checksum(message), flags=flags_to_send,data=message)
            if simulate_error:
                packet.checksum = 0
            if push_to_front:
                with self.queue_lock:
                    self.data_queue.appendleft(packet)
            elif not push_to_front:
                with self.queue_lock:
                    self.data_queue.append(packet)

        elif len(message) > FRAGMENT_SIZE:  # split data to be sent into multiple fragments if needed
            fragments = [message[i:i + FRAGMENT_SIZE] for i in range(0, len(message), FRAGMENT_SIZE)]
            random_corrupted_packet_id = random.randint(0, len(fragments) - 1) if simulate_error else -1
            for i, fragment in enumerate(fragments):
                if i == len(fragments) - 1:  # if it is last fragment, mark it with FRP/ACK
                    fragment_flag = Flags.FRP_LAST
                else:
                    fragment_flag = Flags.FRP

                if i == random_corrupted_packet_id and simulate_error:
                    packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, identification=i,
                                    checksum=0, flags=fragment_flag, data=fragment)
                else:
                    packet = Packet(seq_num=self.seq_num, ack_num=self.ack_num, identification=i,
                                    checksum=Functions.calc_checksum(fragment.encode()), flags=fragment_flag, data=fragment)
                with self.queue_lock:
                    self.data_queue.append(packet)
        return
#### SENDING AND RECEIVING #############################################################################################
    def send_data_from_queue(self): # is in send_thread thread
        fragment_count_to_send = 0
        last_printed_percentage = -1
        fragment_count_to_receive = ""
        frp_size = 0
        terminate_connection = False

        while True:
            if not self.data_queue: # if queue is empty, start keep alive
                continue

            ######## prepare the package #######################
            with self.queue_lock:
                packet_to_send = self.data_queue[0] # take first from queue
                packet_to_send.seq_num = self.seq_num # set current seq
                packet_to_send.ack_num = self.ack_num # set current ack

                if not packet_to_send.flags in {Flags.KAL, Flags.KAL_ACK}:
                    self.do_keep_alive.clear()
                    global kal_delivery_error
                    kal_delivery_error = 0

                # data for printing
                if packet_to_send.flags == Flags.F_INFO:
                    fragment_count_to_receive = packet_to_send.data.decode()
                    fragment_count_to_send = packet_to_send.data.decode().split(":")[2]
                    print()
                    print(f"\n\n   0%  - - 25%  - - 50%  - - 75%  - -  100%    (packets sent)")
                if packet_to_send.flags == Flags.FRP:
                    fragment_count_to_send += 1
                    frp_size += len(packet_to_send.data)

                ######## send the packet ##########################
                try:
                    self.send_socket.sendto(packet_to_send.concatenate(), self.peer_address)
                except OSError:
                    continue
                # print(f"sent: {packet_to_send.flags}")

                #### TERMINATION ##################################
                if packet_to_send.flags == Flags.TER:
                    print(f"\n\n1. Sent TER - starting termination of connection")
                    terminate_connection = True
                elif packet_to_send.flags == Flags.TER_ACK:
                    print("2. Sent TER/ACK - termination is about to finish")
                elif packet_to_send.flags == Flags.ACK and terminate_connection:
                    print("3. Sent ACK - connection ended")
                    self.terminate_listening = True
                    return

                #### flags that do not need to be acknowledged ####
                if packet_to_send.flags in {Flags.ACK, Flags.NACK, Flags.TER, Flags.TER_ACK, Flags.KAL, Flags.KAL_ACK}:
                    self.data_queue.popleft()
                    continue

            #### Threading locking mechanism ####
            if packet_to_send.flags in {Flags.F_INFO, Flags.FRP}:
                self.enable_input.clear() # if we send F_INFO, lock the input
            if packet_to_send.flags in {Flags.LAST_FILE, Flags.FRP_LAST}:
                self.enable_input.set() # unlock the input if not sending
            if packet_to_send.flags == Flags.FRP_LAST: print("Last fragment sent")
            ####### STOP & WAIT ########################################################################################
            self.received_ack.clear()
            if self.received_ack.wait(timeout=5.0): # or self.received_nack.wait(timeout=5.0): hh
                if self.received_NACK.is_set():
                    print("\n!!! Received NACK - resending packet !!!\n")
                    # recauculate checksum
                    packet_to_send.checksum = Functions.calc_checksum(packet_to_send.data)
                    self.received_NACK.clear()
                    continue
                ###### print sending status if sending file ######
                if packet_to_send.flags == Flags.FILE:
                    progress = (packet_to_send.identification * 100 / int(fragment_count_to_send))
                    current_percentage = int(progress)
                    if current_percentage // 5 > last_printed_percentage:
                        print("##", end='', flush=True)
                        last_printed_percentage = current_percentage // 5
                if packet_to_send.flags == Flags.LAST_FILE:
                    # print(f"\n\nSending succesfuly completed! \n")
                    file_name = fragment_count_to_receive.split(":")[0]
                    file_size = fragment_count_to_receive.split(":")[1]
                    print(f"\n\nFile '{file_name}' was sent successfully. \nSize: {file_size}B. \nFragments send:{fragment_count_to_send} "
                          f"\nFragment size: {FRAGMENT_SIZE}B \nLast fragment size: {len(packet_to_send.data)}")
                    last_printed_percentage = -1
                if packet_to_send.flags == Flags.FRP_LAST:
                    print(f"\nFragmented message was sent successfully. \nSize: {frp_size + len(packet_to_send.data)}B. \nFragments send:{fragment_count_to_send+1} "
                          f"\nFragment size: {FRAGMENT_SIZE}B \nLast fragment size: {len(packet_to_send.data)}")
                    fragment_count_to_send = 0
                    frp_size = 0

                self.seq_num += len(packet_to_send.data)
                with self.queue_lock:
                    self.data_queue.popleft()
                continue
            else:
                self.do_keep_alive.set()
                while True:
                    if self.received_NACK.is_set():
                        print("\n!!! Received NACK - resending packet !!!\n")
                        # recauculate checksum
                        packet_to_send.checksum = Functions.calc_checksum(packet_to_send.data)
                        self.received_NACK.clear()
                    else:
                        print("!ACK not received, resending packet!")

                    self.received_ack.clear()
                    try:
                        self.send_socket.sendto(packet_to_send.concatenate(), self.peer_address)
                    except OSError:
                        pass

                    if self.received_ack.wait(timeout=5.0):
                        # print("Ack received")
                        self.seq_num += len(packet_to_send.data)
                        with self.queue_lock:
                            self.data_queue.popleft()
                        break
        return
    def receive_data(self): # is NOT in thread so the program can terminate later
        fragments = [] # array to store received fragments
        file_to_receive_metadata = ""
        transfer_start_time = None
        corrupted_packages = 0
        terminate_connection = False
        prev_received_identification = 1

        sha256 = hashlib.sha256()

        # set timeout for waiting
        self.receiving_socket.settimeout(5.0)
        while not self.terminate_listening:
            try:
                # receive data
                packet_data, addr = self.receiving_socket.recvfrom(1500)
                rec_packet = Packet.deconcatenate(packet_data)

                if rec_packet.flags not in {Flags.KAL, Flags.KAL_ACK, Flags.ACK}:
                    # print("daco som dostal")
                    self.do_keep_alive.clear()

                ####### rec. ACK/NACK ##################################################################################
                if rec_packet.flags == Flags.ACK: # and rec_packet.ack_num == self.seq_num + 1: - if want to check seq/ack
                    self.received_ack.set() # this stays only in this if
                    self.ack_num = rec_packet.seq_num + 1
                    # print("ack received")
                    if terminate_connection:
                        print("3. Received ACK - connection ended")
                        return
                    else: continue
                elif rec_packet.flags == Flags.NACK:
                    self.received_NACK.set()
                    self.received_ack.set()
                ####### TERMINATON #####################################################################################
                elif rec_packet.flags == Flags.TER:
                    print("\n\n1. Received TER - starting termination of connection")
                    self.ack_num = rec_packet.seq_num + 1
                    self.enqueue_message(flags_to_send=Flags.TER_ACK, push_to_front=True)
                    terminate_connection = True
                elif rec_packet.flags == Flags.TER_ACK:
                    print("2. Received TER/ACK - termination is about to finish")
                    self.ack_num = rec_packet.seq_num + 1
                    self.enqueue_message(flags_to_send=Flags.ACK, push_to_front=True)
                ####### Keep Alive #####################################################################################
                elif rec_packet.flags == Flags.KAL:
                    self.ack_num = rec_packet.seq_num + 1
                    self.enqueue_message(flags_to_send=Flags.KAL_ACK, push_to_front=True)
                elif rec_packet.flags == Flags.KAL_ACK:
                    self.successful_kal_delivery.set()
                ####### FRagmented Packet ##############################################################################
                elif rec_packet.flags == Flags.FRP or rec_packet.flags == Flags.FRP_LAST:
                    if not Functions.compare_checksum(rec_packet.checksum, rec_packet.data): # if checksum corrupted
                        self.enqueue_message(flags_to_send=Flags.NACK, push_to_front=True)  # notify that message came currupted

                        print(
                            f"received fragment -> id:{rec_packet.identification}, seq:{rec_packet.seq_num}, received damaged!\n")
                        continue
                    print(f"received fragment -> id:{rec_packet.identification}, seq:{rec_packet.seq_num}, received succesfully")
                    if prev_received_identification != rec_packet.identification:
                        fragments.append(rec_packet)
                        if rec_packet.identification == 1: transfer_start_time = time.time()
                    prev_received_identification = rec_packet.identification

                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True) # send ack
                    self.ack_num += rec_packet.seq_num + 1

                    if rec_packet.flags == Flags.FRP_LAST:
                        message, number_of_fragments = Functions.rebuild_fragmented_message(fragments)

                        print(f"\n<<<< Received <<<<\n{message.decode()} (message of {len(message)} bytes was Received as "
                              f"{number_of_fragments} fragments in {time.time() - transfer_start_time:.2f} seconds)\n<<<< Received <<<< \n")
                        fragments = []  # reset fragments
                        prev_received_identification = 1
                    continue
                ####### Change Fragment Limit ##########################################################################
                elif rec_packet.flags == Flags.CFL:
                    global FRAGMENT_SIZE
                    old_limit = FRAGMENT_SIZE
                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True) # send ack
                    FRAGMENT_SIZE = int(rec_packet.data.decode())
                    print("\n\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    print(f"Other peer has just changed fragmentation limit from {old_limit} to {FRAGMENT_SIZE}")
                    print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                    continue
                ####### Ordinary messages ##############################################################################
                elif rec_packet.flags == Flags.NONE: # is an ordinary message
                    if not Functions.compare_checksum(rec_packet.checksum, rec_packet.data): # if checksum corrupted
                        self.enqueue_message(flags_to_send=Flags.NACK, push_to_front=True)  # notify that message came currupted
                        continue

                    print(f"\n\n<<<< Received <<<<\n{rec_packet.data.decode()} \n<<<< Received <<<< \n")
                    #### send ACK to signal data were received correctly
                    self.ack_num = rec_packet.seq_num + len(rec_packet.data)
                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True) # send ack
                    continue
                ####### File handling ##################################################################################
                elif rec_packet.flags == Flags.F_INFO:
                    if not Functions.compare_checksum(rec_packet.checksum, rec_packet.data): # if checksum corrupted
                        corrupted_packages += 1
                        self.enqueue_message(flags_to_send=Flags.NACK, push_to_front=True)  # notify that message came currupted
                        continue

                    self.enable_input.clear()

                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True)  # send ack
                    fragments = [] # empty fragmetns from older transfer if needed

                    file_to_receive_metadata = rec_packet.data
                    transfer_start_time = time.time()

                    print(f"\n< Received file transfer request for '{file_to_receive_metadata.decode()}' >")
                    continue
                elif rec_packet.flags == Flags.FILE:
                    if not Functions.compare_checksum(rec_packet.checksum, rec_packet.data): # if checksum corrupted
                        print(f"received file fragment -> id:{rec_packet.identification}, seq:{rec_packet.seq_num}, received damaged!\n")
                        corrupted_packages += 1
                        self.enqueue_message(flags_to_send=Flags.NACK, push_to_front=True) # notify that message came currupted
                        continue
                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True)  # send ack
                    print(f"received file fragment -> id:{rec_packet.identification}, seq:{rec_packet.seq_num}, received succesfully")

                    if prev_received_identification != rec_packet.identification:
                        fragments.append(rec_packet)
                        sha256.update(rec_packet.data)

                    prev_received_identification = rec_packet.identification

                    continue
                elif rec_packet.flags == Flags.LAST_FILE:
                    if not Functions.compare_checksum(rec_packet.checksum, rec_packet.data): # if checksum corrupted
                        print(
                            f"received file fragment -> id:{rec_packet.identification}, seq:{rec_packet.seq_num}, received damaged!\n")
                        corrupted_packages += 1
                        self.enqueue_message(flags_to_send=Flags.NACK, push_to_front=True)  # notify that message came currupted
                        continue
                    self.enqueue_message("", flags_to_send=Flags.ACK, push_to_front=True)  # send ack
                    # fragments.append(rec_packet)

                    recv_hash = rec_packet.data.decode()
                    calc_hash = sha256.hexdigest()

                    if recv_hash == calc_hash:
                        print(f"\nhashes match: {recv_hash}")
                    elif recv_hash != calc_hash:
                        print(f"\nhashes do not match: {recv_hash}/{calc_hash}")

                    self.enable_input.set()
                    data_size = file_to_receive_metadata.decode().split(":")[1]
                    print(f"\n\nAll packages received in {time.time() - transfer_start_time:.2f} seconds \n"
                          f"{corrupted_packages}/{len(fragments)} packages lost\n"
                          f"Size of received file: {data_size} bytes")
                    print("Enter desired path to save file: ")

                    # start thread to merge fragments together but do not block main program
                    merge_file_fragments_thread = threading.Thread(target=self.merge_file_fragments,
                                                                   args=(file_to_receive_metadata, fragments))
                    merge_file_fragments_thread.daemon = True
                    merge_file_fragments_thread.start()
                    # reset variables
                    fragments = []
                    continue

            except socket.timeout:
                # print("nic som nedostal")
                self.do_keep_alive.set()
                continue
            except OSError:
                continue
#### FILE RECEIVING ####################################################################################################
    def merge_file_fragments(self, file_to_receive_metadata, fragments):
        self.enable_input.set() # unfreeze input
        self.do_keep_alive.clear()

        self.direct_input_to_main_control.clear() # turn off input for main functionality to receive data here
        while True:
            save_path = self.command_queue.get()
            if os.path.isdir(save_path):
                print("~~ saving file, please wait ~~")
                break # Exit the loop if the path exists
            else:
                print("File path does not exist. Please enter valid path again.")

        sorted_fragments = sorted(fragments, key=lambda frag: frag.identification)

        merged_file = b''
        for fragment in sorted_fragments: merged_file += fragment.data
        file_name, file_size, num_fragments = file_to_receive_metadata.decode().split(":")
        file_path = os.path.join(save_path, file_name)
        with open(file_path, 'wb') as f:
            f.write(merged_file)
        print(f"File \"{file_name}\" saved to: {file_path}")
        self.direct_input_to_main_control.set() # direct messages again to main input handler
        self.do_keep_alive.set()
        return
#### PROGRAM CONTROL ###################################################################################################
    def input_handler(self):
        print("If you don't know what you can do, enter 'help' or 'man'")
        print("\n~$ ", end='', flush=True)
        self.enable_input.set()
        self.direct_input_to_main_control.set()
        while True:
            self.enable_input.wait() # wait untill can input again
            command = input().strip()
            self.command_queue.put(command)
    def manage_user_input(self): # is in input_thread thread
        while True:
            self.enable_input.wait()

            if self.command_queue.empty() or not self.direct_input_to_main_control.is_set():
                continue
            choice = self.command_queue.get()

            try:
                if choice == "help" or choice == "man": # help / man
                    Functions.info_menu()
                    continue
                elif choice == "m" or choice == "ErrM": # message
                    print("\n>>>>> Sent >>>>>>>")
                    message = self.command_queue.get()
                    print(">>>>> Sent >>>>>>>\n")
                    if choice == "ErrM": self.enqueue_message(message=message, simulate_error=True)
                    else: self.enqueue_message(message=message)
                    continue
                elif choice == "f" or choice == "ErrF": # file
                    print("Enter file path")
                    file_path = self.command_queue.get()
                    if not os.path.exists(file_path):
                        print("This path does not exist. Please enter valid one.")
                    else:
                        if choice == "ErrF": self.enqueue_file(file_path, simulate_error=True)
                        else: self.enqueue_file(file_path)
                    continue
                elif choice == "cfl": # change fragment limit
                    global FRAGMENT_SIZE
                    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
                    print(f"Fragment size is currently set to {FRAGMENT_SIZE}")
                    print("Enter 'q' for quit   or    enter new fragment limit (or 'MAX' to set max fragments possible): ")
                    new_limit = self.command_queue.get()
                    if new_limit == 'q':
                        print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                        continue
                    else:
                        if new_limit == 'MAX':
                            new_limit = str(MAX_FRAGMENT_SIZE)
                        try:
                            new_limit = int(new_limit)  # Try converting input to an integer
                            if new_limit > MAX_FRAGMENT_SIZE or new_limit < 1:
                                print(f"Cannot change fragmentation limit to {new_limit}.")
                                print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                                continue
                            else:
                                print(f"Changed fragmentation limit from {FRAGMENT_SIZE} to {new_limit}")
                                FRAGMENT_SIZE = int(new_limit)
                                self.enqueue_message(str(FRAGMENT_SIZE), Flags.CFL, True)
                                print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                        except ValueError:
                            print("Invalid input. Please enter a number, 'MAX', or 'q' to quit.")
                            print("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n")
                            continue
                elif choice == "!q" or choice == "quit":
                    self.enqueue_message(flags_to_send=Flags.TER, push_to_front=True)
                    return
                else:
                    print("invalid command")
            finally:
                print("\n~$ ", end='', flush=True)

if __name__ == '__main__':
    # MY_IP = input("Enter YOUR IP address: ")
    # PEERS_IP = input("Enter PEER's IP address: ")
    # PEER_SEND_PORT = int(input("Enter your send port: "))
    # PEER_LISTEN_PORT = int(input("Enter your listening port:"))

    ## FOR LOCALHOST TESTING
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
    input_manage_thread = threading.Thread(target=peer.input_handler, daemon=True)
    input_thread = threading.Thread(target=peer.manage_user_input, daemon=True)
    send_thread = threading.Thread(target=peer.send_data_from_queue, daemon=True)
    keep_alive_thread = threading.Thread(target=peer.manage_keep_alive, daemon=True)

    input_manage_thread.start()
    input_thread.start()
    send_thread.start()
    keep_alive_thread.start()
    peer.receive_data()