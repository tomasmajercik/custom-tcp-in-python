class Packet:
    def __init__(self, message, seq_num = 0, ack_num=0, flags=0):
        self.message = message
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags

    def concatenate(self):
        return f"{self.seq_num}|{self.ack_num}|{self.flags:03b}|{self.message}"

    def get_message(self):
        # parts = encoded_packet.split('|', 3)
        # message = parts[3]
        return self.message

    @staticmethod
    def deconcatenate(packet_str):
        parts = packet_str.split('|')
        seq_num = int(parts[0])
        ack_num = int(parts[1])
        flags = int(parts[2], 2)  # Parse binary string
        message = parts[3]
        return Packet(message, seq_num, ack_num, flags)

    #co mi treba dokoncit
    # fin ale podobne ako tcp handshake
    # ak sa nevrati ack tak resendnut
    # spravit poriadne ten stop and wait
