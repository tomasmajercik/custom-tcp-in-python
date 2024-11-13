import crcmod

class Functions:

    @staticmethod
    def info_menu():
        print("MENU:")
        print("'m' for message | 'f' for file | 'cfl' for info or change fragmentation size | '!q / !quit' for quit")

    @staticmethod
    def calc_checksum(message):
        if isinstance(message, str):
            message = message.encode()  # Convert to bytes if it's a string
        crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF,
                                     xorOut=0x0000)  # 0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
        checksum = crc16_func(message)
        return checksum

    @staticmethod
    def rebuild_fragmented_message(fragments):
        full_message = b''
        expeted_id = fragments[0].identification

        for fragment in fragments:
            if fragment.checksum != Functions.calc_checksum(fragment.data):
                print("Error: Checksum mismatch in fragment.")
                return None

            if fragment.identification != expeted_id:
                print("Error: Identification mismatch in fragment.")

            full_message += fragment.data
            expeted_id += 1
        return full_message, expeted_id