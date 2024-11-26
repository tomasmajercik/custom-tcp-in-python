import crcmod

class Functions:

    @staticmethod
    def info_menu():
        print("\n*************************************")
        print("MENU:")
        print("'m' to send message\n"
              "'f' to send file\n"
              "'cfl' to check fragmentation size or change it \n"
              "'!q or quit' to quit\n"
              "'ErrM' to simulate error while sending message in fragments\n"
              "'ErrF' to simulate error while sending files in fragments\n"
              "'help/man' for menu")
        print("*************************************\n")

    @staticmethod
    def calc_checksum(data):
        if isinstance(data, str):
            data = data.encode()  # Convert to bytes if it's a string
        crc16_func = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF,
                                     xorOut=0x0000)  # 0x11021: This is the CRC-16-CCITT polynomial; initCrc=0xFFFF: This initializes the CRC register; xorOut=0x0000: This value is XORed with the final CRC value to complete the checksum.
        checksum = crc16_func(data)
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

    @staticmethod
    def compare_checksum(received_checksum,received_message):
        if received_checksum == Functions.calc_checksum(received_message):
            return True
        else:
            print("\nChecksum does not match - message corrupted")
            return False
    @staticmethod
    def caesar(message="", coeficient=0):
        shifted_message = ""

        for letter in message:
            if letter.isalpha():
                start = ord('A') if letter.isupper() else ord('a') # ord should give ASCII value of char
                shifted = chr((ord(letter) - start + coeficient) % 26 + start)
                shifted_message += shifted
            else:
                shifted_message += letter # keep non letters unchanged

        return shifted_message
