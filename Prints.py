import time
class Prints:

    @staticmethod
    def menu():
        time.sleep(0.1)
        print("\nMENU:")
        # print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
        print("'m' for message | 'f' for file | '!q / !quit' for quit")
        choice = input("Choose an option: ").strip()
        return choice

    @staticmethod
    def info_menu():
        print("MENU:")
        # print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
        print("'m' for message | 'f' for file | '!q / !quit' for quit")

    @staticmethod
    def start_termination():
        print(f"\n\n #Another peer terminates the connection!")
        print(f"1. RECEIVED termination TER")

    @staticmethod
    def checksum_err():
        print("! Checksum does not match !")

    @staticmethod
    def out_of_order_err():
        print("!!Out of order packet received, ignoring!!")

    @staticmethod
    def received_fragmented_package(packet, last=False):
        print(f"\n\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        if not last:
            print(f"Received fragment: {packet.seq_num}|{packet.ack_num}|{packet.identification}|{packet.checksum}|{packet.flags}|{packet.message}")
        if last:
            print(
                f"Received last fragment: {packet.seq_num}|{packet.ack_num}|{packet.identification}|{packet.checksum}|{packet.flags}|{packet.message}")
        print(f"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n")

    @staticmethod
    def received_joined_fragments(data):
        print(f"\n\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        print(f"Received: {data}")
        print(f"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n")

    @staticmethod
    def received_package(packet):
        print(f"\n\n<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
        print(f"Received: {packet.seq_num}|{packet.ack_num}|{packet.checksum}|{packet.flags}|{packet.message}")
        print(f"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n")

    @staticmethod
    def send_packet(packet):
        print(f"\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> \n"
              f"Sent: {packet.seq_num}|{packet.ack_num}|{packet.checksum}|{packet.flags}|{packet.message}")
