class Packet:
    def __init__(self, message):
        self.message = message

    def concatenate(self):
        return f"{self.message}"

    def get_message(self):
        # parts = encoded_packet.split('|', 3)
        # message = parts[3]
        return self.message