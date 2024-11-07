import threading
import socket

SYN = 0b0001
ACK = 0b0010
SYN_ACK = 0b0011
CFL = 0b0100
FRP = 0b1000
KAL = 0b1001
NACK = 0b1101
TER = 0b1100
TER_ACK = 0b1110

from Packet import Packet

class MessageHandler:
    def __init__(self, peer):
        self.peer = peer
        self.successful_delivery = threading.Event()


    def send_message(self, message):
        retries = 0
        max_retries = 5

        while retries < max_retries:
            packet = Packet(message, seq_num=self.peer.seq_num, ack_num=self.peer.ack_num, flags=0b000)  # build a packet
            # Send the packet
            self.peer.send_socket.sendto(packet.concatenate(), self.peer.peer_address)

            print(f"\n>>>>")
            print(f"__________________________________________")
            print(f"Sent >> {message}")
            print(f"____________________________________________")
            self.successful_delivery.clear()

            if self.successful_delivery.wait(timeout=5):
                print("<<<<")
                self.peer.seq_num += len(message) # Update seq_num based on message length
                break  # Exit the loop if message was successfully delivered
            else:
                print(f"Acknowledgment not received, retrying... (Attempt {retries + 1})")
                retries += 1

        if retries == max_retries:
            print(f"Failed to deliver the message after {max_retries} attempts")

    def receive_messages(self):
        while not self.peer.freeze_loops:
            try:
                data, addr = self.peer.receiving_socket.recvfrom(1024)
                packet = Packet.deconcatenate(data)

                if packet.flags == TER:
                    print(f"\n\n #Another peer terminates the connection!")
                    print(f"1. RECEIVED termination TER: {packet.concatenate()}")
                    self.peer.freeze_loops = True
                    if self.peer.respect_terminate_connection():
                        self.peer.receiving_socket.close()
                        self.peer.kill_communication = True
                        # os._exit(0)
                    return

                if packet.flags == ACK:
                    self.successful_delivery.set()

                elif packet.seq_num == self.peer.ack_num:
                    self.peer.ack_num += len(packet.get_message())  # add length of message to my ack_num
                    ack_packet = Packet("", seq_num=self.peer.seq_num, ack_num=self.peer.ack_num, flags=ACK)
                    self.peer.send_socket.sendto(ack_packet.concatenate(), self.peer.peer_address)

                    if packet.flags != ACK:
                        print(f"\n__________________________________________")
                        print(f"Received << {packet.message}")
                        print(f"____________________________________________\n")

                else:
                    print("!!Out of order packet received, ignoring!!")
                    # Send an acknowledgment for the last valid packet
                    # ask for lost package

            except socket.timeout:
                continue