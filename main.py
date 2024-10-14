import socket
import threading


class Peer:
    def __init__(self, host, listen_port, send_port):
        self.id = (host, listen_port)
        self.send_port = send_port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(self.id)
        self.peer_adress =  (host, self.send_port)

    def receive_messages(self):
        while True:
            try:
                data, addr = self.socket.recvfrom(1024)
                print(f"Recieved from {addr}: {data.decode()}")

            except Exception as e:
                print(f"Error recieving message: {e}")
                break

    def send_message(self):
        while True:
            message = input("Enter message: (!quit to quit) ")
            if message == "!quit":
                self.socket.close()
                break
            try:
                self.socket.sendto(message.encode(), self.peer_adress) #sprav classu packet kde bude cely header
            except Exception as e:
                print(f"Error sending message to {peer}: {e}")



if __name__ == '__main__':
    IP = "localhost"

    whos_this = input("peer one (1) or peer two (2): ")
    if whos_this == "1":
        PEER_LISTEN_PORT = 3000
        PEER_SEND_PORT = 2000
    else:
        PEER_LISTEN_PORT = 2000
        PEER_SEND_PORT = 3000


    peer = Peer(IP, PEER_LISTEN_PORT, PEER_SEND_PORT)

    receive_thread = threading.Thread(target=peer.receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    peer.send_message()

    #65% 16:42