import struct

class Packet:

    HEADER_FORMAT = 'iiHB'  # two integers, one 16-bit unsigned short for checksum (16 bits), and one byte for flags

    def __init__(self, message, seq_num = 0, ack_num=0, checksum=0, flags=0):
        self.message = message
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.checksum = checksum
        self.flags = flags

    def concatenate(self):

        # Pack header fields and message length
        header = struct.pack(self.HEADER_FORMAT, self.seq_num, self.ack_num, self.checksum, self.flags)
        # Combine header and message
        return header + self.message.encode('utf-8')

    @staticmethod
    def deconcatenate(packet):
        # Calculate the header size based on HEADER_FORMAT
        header_size = struct.calcsize(Packet.HEADER_FORMAT)
        # Unpack the header fields
        seq_num, ack_num, checksum, flags = struct.unpack(Packet.HEADER_FORMAT, packet[:header_size])

        # Decode the message from the remaining bytes
        message = packet[header_size:].decode('utf-8')

        return Packet(message, seq_num, ack_num, checksum, flags)

