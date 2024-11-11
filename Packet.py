import struct

class Packet:

    HEADER_FORMAT = 'IIIHB'  # two integers, one 16-bit unsigned short for checksum (16 bits), and one byte for flags

    def __init__(self, message, seq_num = 0, ack_num=0, identification=0, checksum=0, flags=0):
        self.message = message
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.identification = identification
        self.checksum = checksum
        self.flags = flags

    def concatenate(self):
        # Pack header fields and message length
        header = struct.pack(self.HEADER_FORMAT, self.seq_num, self.ack_num, self.identification, self.checksum, self.flags)
        # Combine header and message
        message_bytes = self.message if isinstance(self.message, bytes) else self.message.encode('utf-8')
        return header + message_bytes

    @staticmethod
    def deconcatenate(packet):
        # Calculate the header size based on HEADER_FORMAT
        header_size = struct.calcsize(Packet.HEADER_FORMAT)
        # Unpack the header fields
        seq_num, ack_num, identification, checksum, flags = struct.unpack(Packet.HEADER_FORMAT, packet[:header_size])

        # Decode the message from the remaining bytes
        # Get the message from the remaining bytes of the packet
        message_bytes = packet[header_size:]

        # Try to decode the message if it's a string, otherwise leave it as bytes
        try:
            # Attempt to decode as UTF-8 string
            message = message_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If it fails to decode, assume it's already in bytes
            message = message_bytes

        return Packet(message, seq_num, ack_num, identification, checksum, flags)

