import struct

class Packet:

    HEADER_FORMAT = 'IIIHB'  # two integers, one 16-bit unsigned short for checksum (16 bits), and one byte for flags

    def __init__(self, seq_num = 0, ack_num=0, identification=0, checksum=0, flags=0, data=""):
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.identification = identification
        self.checksum = checksum
        self.flags = flags
        # Ensure data is bytes - if already in bytes, let it be, if not (is a string), encode it using utf-8
        self.data = data if isinstance(data, bytes) else data.encode('utf-8')


    def concatenate(self):
        header = struct.pack(self.HEADER_FORMAT, self.seq_num, self.ack_num, self.identification, self.checksum,
                             self.flags)
        return header + self.data # add bytes data

    @staticmethod
    def deconcatenate(data_bytes):
        header_size = struct.calcsize(Packet.HEADER_FORMAT)
        header_data = data_bytes[:header_size]
        data = data_bytes[header_size:]

        # Unpack the header
        seq_num, ack_num, identification, checksum, flags = struct.unpack(Packet.HEADER_FORMAT, header_data)

        decoded_data = data
        try:
            # Attempt to decode as UTF-8 for text data
            decoded_data = data.decode('utf-8')
        except UnicodeDecodeError:
            # Keep as bytes if decoding fails
            pass

            # Create and return a Packet instance
        return Packet(seq_num, ack_num, identification, checksum, flags, decoded_data)

