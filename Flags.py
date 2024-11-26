class Flags:

    NONE = 0b0000 #0
    ACK = 0b0010 #2
    NACK = 0b1101 #13
    #
    SYN = 0b0001 #1
    SYN_ACK = 0b0011 #3
    #
    CFL = 0b0100 #4
    FRP = 0b1000 #8
    FRP_LAST = 0b1010 #10
    #
    KAL = 0b1001 #0
    KAL_ACK = 0b1011 #11
    #
    TER = 0b1100 #12
    TER_ACK = 0b1110 #14
    #
    F_INFO = 0b1111 #15
    FILE = 0b0101 #5
    LAST_FILE = 0b0110 #6
    #