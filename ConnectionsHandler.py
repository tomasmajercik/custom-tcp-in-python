import socket

from Packet import Packet

SYN = 0b0001
ACK = 0b0010
SYN_ACK = 0b0011
CFL = 0b0100
FRP = 0b1000
KAL = 0b1001
NACK = 0b1101
TER = 0b1100
TER_ACK = 0b1110

class ConnectionsHandler:
    def __init__(self, peer):
        self.peer = peer
        self.seq_num = peer.seq_num
        self.ack_num = peer.ack_num
        self.retry_interval = 2
        self.max_retries = 15

    def handshake(self):
        retry_interval = 2
        max_retries = 15
        retries = 0

        # Set timeout for waiting on incoming packets
        self.peer.receiving_socket.settimeout(retry_interval)

        while retries < max_retries:
            try:
                try:
                    data, addr = self.peer.receiving_socket.recvfrom(1024)
                    received_packet = Packet.deconcatenate(data)

                    if received_packet.flags == SYN:  # Received SYN from the other peer
                        print(f"\nReceived handshake SYN")
                        self.ack_num = received_packet.seq_num + 1
                        SYN_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=SYN_ACK)
                        self.peer.send_socket.sendto(SYN_ACK_packet.concatenate(), self.peer.peer_address)
                        self.seq_num += 1
                        print(f"Sent handshake SYN/ACK")

                    elif received_packet.flags == SYN_ACK:  # Received SYN/ACK in response to our SYN
                        print(f"Received handshake SYN/ACK")
                        self.ack_num = received_packet.seq_num + 1
                        ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=ACK)
                        self.peer.send_socket.sendto(ACK_packet.concatenate(), self.peer.peer_address)
                        self.seq_num += 1
                        print(f"Sent handshake ACK")
                        print(
                            f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                    elif received_packet.flags == ACK:  # Received final ACK confirming the handshake
                        self.ack_num = received_packet.seq_num + 1
                        print(f"Received handshake ACK")
                        print(
                            f"\n## Handshake successful, connection initialized seq: {self.seq_num} ack:{self.ack_num}")
                        return True

                except socket.timeout:
                    # If nothing was received, initiate the handshake by sending SYN
                    if retries == 0:
                        SYN_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=SYN)
                        self.peer.send_socket.sendto(SYN_packet.concatenate(), self.peer.peer_address)
                        print(f"\nSent handshake SYN (attempt {retries + 1})")

                retries += 1

            except socket.timeout:
                print(f"Retrying... (attempt {retries + 1})")

        print(f"Handshake timeout after {max_retries} retries")
        self.peer.receiving_socket.close()
        return False

    def start_terminate_connection(self):
        print("#starting termination process")
        retry_interval = 2
        max_retries = 15
        retries = 0

        while retries < max_retries:
            try:
                # send TER
                TER_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=TER)  # SYN
                self.peer.send_socket.sendto(TER_packet.concatenate(), self.peer.peer_address)
                print(f"\n1. SENT termination: {TER_packet.concatenate()} (attempt {retries + 1})")
                retries += 1

                # Expect TER/ACK
                self.peer.receiving_socket.settimeout(retry_interval)  # if nothing received in interval, do not wait
                data, addr = self.peer.receiving_socket.recvfrom(1024)

                TER_ACK_packet = Packet.deconcatenate(data)

                if TER_ACK_packet.flags == TER_ACK:  # if TER/ACK received
                    print(f"2. RECEIVED termination TER/ACK: {TER_ACK_packet.concatenate()}")
                    self.seq_num += 1  # sent one phantom byte
                    self.ack_num = TER_ACK_packet.seq_num + 1  # Update ACK number to one more than received seq num
                    ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=ACK)  # ACK

                    self.peer.send_socket.sendto(ACK_packet.concatenate(), self.peer.peer_address)
                    print(f"3. SENT termination ACK: {ACK_packet.concatenate()}")
                    self.seq_num += 1  # after succesfull handshake, "I am waiting for this package"

                    self.peer.receiving_socket.close()
                    self.peer.kill_communication = True
                    print(f"\n## Termination successful, connection ended")
                    return



            except socket.timeout:
                print(f"retrying termination... (attempt {retries + 1})")

    def respect_terminate_connection(self):
        TER_ACK_packet = Packet("", seq_num=self.seq_num, ack_num=self.ack_num, flags=TER_ACK)  # send SYN-ACK
        self.peer.send_socket.sendto(TER_ACK_packet.concatenate(), self.peer.peer_address)
        print(f"2. Sent termination TER/ACK: {TER_ACK_packet.concatenate()}")

        while True:
            data, addr = self.peer.receiving_socket.recvfrom(1024)  # recieve ACK
            ACK_packet = Packet.deconcatenate(data)

            if ACK_packet.flags == ACK:  # if ACK received
                print(f"3. Received termination ACK: {ACK_packet.concatenate()}")
                print(f"\n##Termination successful, connection ended")
                self.peer.kill_communication = True
                # self.ack_num += 1  # after succesfull handshake, "I am waiting for this package"
                return True
