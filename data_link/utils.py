import re

class Utils:
    def __init__(self, FLAG, MESSAGE_SIZE):
        self.FLAG = FLAG
        self.MESSAGE_SIZE = MESSAGE_SIZE

    def parse(self, message):
        maxIncrease = int(self.MESSAGE_SIZE/(len(self.FLAG)-2))+1

        minMessage = self.MESSAGE_SIZE
        maxMessageSize = self.MESSAGE_SIZE + maxIncrease
        flagAddSize = 2 * len(self.FLAG)

        p = re.compile(''.join(list(map(lambda x: str(x),self.FLAG))))
        pos = []

        for match in re.finditer(p, message):
            pos.append([match.start(0),match.end(0)])
        
        possibilities = []
        for idx in range(1,len(pos)):
            before = pos[idx-1]
            actual = pos[idx]
            possibilities.append(message[before[0]:actual[1]])

        values = list(filter(lambda x: len(x) >= flagAddSize + minMessage and len(x) <= flagAddSize + maxMessageSize, possibilities))
        return values

    def compare(self, send, received):
        idxSent = 0
        idxRec = 0
        match = 0
        last_rec = 0
        last_sent = 0
        while idxRec < len(received):
            if idxSent == len(send):
                idxSent = last_sent
                if idxRec == last_rec + 1:
                    idxRec += 1
                else:
                    idxRec = last_rec + 1
        
            elif send[idxSent] == received[idxRec]:
                match += 1
                idxRec += 1
                idxSent += 1
                last_rec = idxRec
                last_sent = idxSent
            else:
                idxSent += 1
        return match

# se = ['01111011100011101011110', '0111100001001001011110', '0111100001001100011110', '0111100110001100011110', '0111100110001101011110', '0111101010110000011110', '0111101101010000011110', '01111000001011101011110', '01111001101110100011110', '0111100111001001011110', '01111000101011101011110', '0111100111010111011110', '0111100110100010011110', '01111011101011011011110', '0111101010010001011110', '0111101010101110011110', '0111101010110001011110', '0111100100110010011110', '01111010010111011011110', '0111100111010001011110', '0111100100001100011110', '01111001101110111011110', '0111100101101000011110', '0111101001110010011110', '0111101110110110011110', '01111000111011000011110', '01111011101100000011110', '0111101000001001011110', '0111101001001110011110', '0111101101101010011110', '0111101110111000011110', '01111000011101010011110', '0111101010100111011110', '0111100111000111011110', '0111101110111011101011110', '0111100100100001011110', '01111011011101110011110', '0111100000010001011110', '0111100101101000011110', '0111101000001100011110', '0111101100010010011110', '0111100111001001011110', '0111100110110110011110', '0111101011101100011110', '0111101010110010011110', '0111100001100100011110', '01111010001110110011110', '0111100010110011011110', '0111100110000001011110', '01111001100111011011110', '01111011001110100011110', '01111011101101011011110', '01111010001011101011110', '01111011011101001011110', '0111101000001010011110', '0111100100111010011110', '0111100010101001011110', '0111101100101100011110', '0111101001010110011110', '01111011011011101011110', '0111100001011100011110', '0111100101001000011110', '0111100101101010011110', '0111101000101110011110', '0111101101000000011110', '01111000111010110011110', '01111001110101010011110', '0111100100010011011110', '0111101101000111011110', '0111101010010001011110', '0111100010110010011110', '0111101100100000011110', '011110001110111011011110', '0111100010100110011110', '011110111010111011011110', '0111100010000010011110', '0111101110010010011110', '01111001110110101011110', '0111101011011010011110', '0111100100011000011110', '0111101010100010011110', '0111101011001000011110', '0111101010100110011110', '0111101011100110011110', '0111100110001001011110', '0111101110110101011110', '01111010111011101011110', '0111100100100101011110', '0111101100101011011110', '01111011101011010011110', '0111101100001001011110', '0111101101001000011110', '0111101010000000011110', '0111101011010100011110', '0111101110000011011110', '0111101010100100011110', '0111101110000001011110', '0111100110100010011110', '0111101010110101011110', '0111101000011001011110', '0111100000110111011110', '0111101001100011011110', '0111100000111010011110', '0111100101100111011110', '011110111011101000011110', '0111100011101010011110', '0111100110100111011110', '0111101100111010011110', '0111100010010000011110', '0111100110100100011110', '0111101001110100011110', '0111100000100010011110', '01111010111010000011110', '0111100010010101011110', '0111101100101010011110', '01111000001110100011110', '01111011100011101011110', '01111011101011001011110', '0111100111010101011110', '0111100100101001011110', '0111100100001100011110', '0111101010110011011110', '0111101000000110011110', '01111001011101100011110', '011110111011101011011110', '0111101110110100011110', '01111000101110101011110', '0111101010110000011110', '0111101001100111011110', '0111101110101101011110', '0111100010000100011110', '0111101011100111011110', '0111100011100110011110', '0111100010001101011110', '01111000111010111011110', '0111101011001001011110', '0111100010010001011110', '0111101010001110011110', '0111101011001101011110', '0111100001100101011110', '011110111011101000011110', '0111100000110001011110', '01111010111011011011110', '0111100001001010011110', '01111001011101100011110', '0111100001110000011110', '0111100011001101011110', '01111011101110010011110', '0111100111001000011110', '0111101011011000011110', '0111100100100101011110', '0111101100011101011110', '0111100001000011011110', '01111001110011101011110', '0111101010011100011110', '0111101001101010011110', '01111011101100100011110', '0111100100011011011110', '0111100001001100011110', '01111011101000000011110', '0111101101000110011110', '0111100001101100011110', '0111100011101001011110', '0111101011100100011110', '0111101011000001011110', '0111101010001100011110', '0111101010011100011110', '0111101001100000011110', '0111101010101001011110', '0111101000011100011110', '0111100101100000011110', '011110010111011101011110', '01111011101010110011110', '0111101110111011011110', '0111100110010000011110', '0111100000011000011110', '0111100001011000011110', '0111101100010101011110', '0111101000110101011110', '0111101001001001011110', '0111100101110101011110', '0111101101000000011110', '0111101101100110011110', '0111100101110100011110', '0111100010000101011110', '0111100000111001011110', '0111100000101011011110', '0111100110000000011110', '0111101100110111011110', '0111100001000110011110', '0111101101001100011110', '01111010111010001011110', '0111100001101010011110', '0111100011100010011110', '0111100000011001011110', '0111100000000110011110', '011110111011101110011110', '011110111011101001011110', '0111100000010110011110', '0111101110111000011110', '0111100100000111011110', '0111101110011010011110', '0111100010010110011110', '0111101011100101011110', '0111101010000111011110', '0111101100111010011110', '01111000101110100011110', '0111101101001011011110', '01111000111011010011110', '0111101100010110011110', '0111101000101010011110', '0111101010100101011110', '0111100010000000011110', '0111101101110000011110', '0111100101100111011110', '011110111010111011011110', '0111100110111010011110', '0111100100000001011110', '01111011000111011011110', '01111000100111010011110', '01111011101110001011110', '0111101001110111011110', '0111101011011011011110', '0111101110011011011110', '0111100010010010011110', '0111101100000100011110', '0111101100101000011110', '0111100000101010011110', '0111100111010011011110', '0111101100100100011110', '0111101010000001011110', '0111101001000010011110', '0111100101001001011110', '0111101110001011011110', '0111101101010000011110', '0111100011011001011110', '01111010001110110011110', '0111100001010110011110', '0111101101010110011110', '01111001011101110011110', '0111100010010110011110', '0111100010000101011110', '0111101101010100011110', '0111100101100001011110', '011110011101110100011110', '01111000011101001011110', '0111100111000110011110', '0111100111000111011110', '0111100001010101011110', '0111100000011010011110', '0111100110001001011110', '0111100100110100011110', '0111101100110000011110', '01111010001110110011110', '0111101000001011011110', '0111101001011101011110', '0111100110010001011110', '0111101001110011011110', '0111100101101110011110', '01111011101001001011110', '0111101001101011011110', '0111101101010011011110', '0111100101000000011110', '01111000111010101011110', '0111101011010111011110', '0111100010010110011110', '01111000110111010011110', '0111101110011010011110', '0111100000111000011110', '01111011101101101011110', '01111011101001000011110', '0111100011011001011110', '011110100111011101011110', '0111101000101100011110', '0111100110000010011110', '0111101100101101011110', '011110111010111010011110', '0111101110011101011110', '0111100000100101011110']
# re = ['01111011100011101011110', '0111100001001001011110', '0111100001001100011110', '0111100110001100011110', '0111100110001101011110', '0111101010110000011110', '0111101101010000011110', '01111000001011101011110', '0111100101101011110', '01111000101011101011110', '0111100111010111011110', '0111100110100010011110', '01111011101011011011110', '0111101010010001011110', '0111101010101011110', '0111100100110010011110', '01111010010111011011110', '0111100111010001011110', '0111100100001100011110', '01111001101110111011110', '0111100101101000011110', '0111101001110010011110', '0111101110110110011110', '01111000111011000011110', '01111011101100000011110', '0111101000001001011110', '0111101001001110011110', '0111101101101010011110', '0111101110111000011110', '01111000011101010011110', '0111101010100111011110', '0111100111000111011110', '0111101110111011101011110', '0111100100100001011110', '01111011011101110011110', '0111100000010001011110', '0111100101101000011110', '0111101000001100011110', '0111101100010010011110', '0111100111001001011110', '0111100110110110011110', '0111101011101100011110', '0111101010110010011110', '0111100110000001011110', '01111001100111011011110', '01111011001110100011110', '01111011101101011011110', '01111010001011101011110', '01111011011101001011110', '0111101000001010011110', '0111100100111010011110', '0111100010101001011110', '0111101100101100011110', '0111101001010110011110', '01111011011011101011110', '0111100001011100011110', '0111100101001000011110', '0111100101101010011110', '0111101000101110011110', '0111101101000000011110', '01111000111010110011110', '01111001110101010011110', '0111100100010011011110', '0111101101000111011110', '0111101010010001011110', '0111100010110010011110', '0111101100100000011110', '011110001110111011011110', '0111100010100110011110', '011110111010111011011110', '0111100010000010011110', '0111101011011010011110', '0111101010100110011110', '0111101011100110011110', '0111100110001001011110', '0111101110110101011110', '01111010111011101011110', '0111100100100101011110', '0111101100101011011110', '01111011101011010011110', '0111101100001001011110', '0111101101001000011110', '0111101010000000011110', '0111101011010100011110', '0111101110000011011110', '0111101010100100011110', '0111101110000001011110', '0111100110100010011110', '0111101010110101011110', '0111101000011001011110', '0111100000110111011110', '0111101001100011011110', '0111100011101010011110', '0111100110100111011110', '0111101100111010011110', '0111100010010000011110', '0111100110100100011110', '0111101001110100011110', '0111100000100010011110', '0111100101011110', '0111101100101010011110', '01111000001110100011110', '01111011100011101011110', '01111011101011001011110', '0111100111010101011110', '0111100100101001011110', '0111100100001100011110', '0111101010110011011110', '0111101000000110011110', '01111001011101100011110', '011110111011101011011110', '0111101110110100011110', '01111000101110101011110', '0111101010110000011110', '0111101001100111011110', '0111101110101101011110', '0111100010000100011110', '0111101011100111011110', '0111100011100110011110', '0111100010001101011110', '01111000111010111011110', '0111101011001001011110', '0111100010010001011110', '0111101011001101011110', '0111100001100101011110', '011110111011101000011110', '0111100000110001011110', '01111010111011011011110', '01111000010010101011110', '0111100001110000011110', '0111100011001101011110', '01111011101110010011110', '0111100111001000011110', '0111101011011000011110', '0111100100100101011110', '0111101100011101011110', '0111100001000011011110', '01111001110011101011110', '0111101010011100011110', '0111101001101010011110', '01111011101100100011110', '0111100100011011011110', '0111100001001100011110', '01111011101000000011110', '0111101101000110011110', '0111100001101100011110', '0111100011101001011110', '0111101011100100011110', '0111101011000001011110', '0111101010001100011110', '0111101010011100011110', '011110000011110', '0111101000011100011110', '0111100101100000011110', '011110010111011101011110', '01111011101010110011110', '0111101110111011011110', '011110011000100011110', '0111101100010101011110', '0111101000110101011110', '0111101001001001011110', '0111100101110101011110', '0111101101000000011110', '0111101101100110011110', '0111100101110100011110', '0111100010000101011110', '0111100000111001011110', '0111100000101011011110', '0111100110000000011110', '0111101100110111011110', '0111100001000110011110', '0111101101001100011110', '01111010111010001011110', '0111100001101010011110', '0111100011100010011110', '0111100000011001011110', '0111100000000110011110', '011110111011101110011110', '011110111011101001011110', '0111100000010110011110', '0111100100000111011110', '0111101110011010011110', '0111100010010110011110', '0111101011100101011110', '0111101010000111011110', '0111101100111010011110', '0111101100010110011110', '0111101000101010011110', '0111101010100101011110', '0111100010000000011110', '0111101101110000011110', '0111100101100111011110', '011110111010111011011110', '0111100110111010011110', '0111100100000001011110', '01111011000111011011110', '01111000100111010011110', '01111011101110001011110', '0111101001110111011110', '0111101011011011011110', '0111101110011011011110', '0111100010010010011110', '0111101100000100011110', '0111101100101000011110', '0111100000101010011110', '0111100111010011011110', '0111101100100100011110', '0111101010000001011110', '0111101001000010011110', '0111100101001001011110', '0111101110001011011110', '0111101101010000011110', '0111100011011001011110', '01111010001110110011110', '0111100001010110011110', '0111101101010110011110', '01111001011101110011110', '0111100010010110011110', '0111100010000101011110', '0111101101010100011110', '0111100101100001011110', '011110011101110100011110', '01111000011101001011110', '0111100111000110011110', '0111100111000111011110', '0111100001010101011110', '0111100000011010011110', '0111100110001001011110', '0111100100110100011110', '0111101100110000011110', '01111010001110110011110', '0111101000001011011110', '0111101001011101011110', '0111100110010001011110', '0111101001110011011110', '0111100101101110011110', '01111011101001001011110', '0111101001101011011110', '0111101101010011011110', '0111100101000000011110', '011110100111011101011110', '011110111010111010011110', '01111000010110101011110']
if __name__ == '__main__':
    pass
    # send = insertMessage()
    # rawMessage = readMessage()
    # receive = parse(rawMessage)
    # print("inserted:", len(send)) 
    # print("read:", len(receive))

    # print("sent:",send )
    # print("read:", receive)
    # # send = ['0111101000100010011110', '0111100001010110011110', '01111001110101011011110', '0111101010001001011110', '01111011101000111011110', '01111011101010110011110', '0111101110010100011110', '01111000110111010011110', '0111101010100000011110', '0111100110000000011110', '0111101100000000011110', '0111100111000011011110', '0111101011000101011110', '011110111011101000011110', '01111001110111010011110', '01111000111010100011110', '011110111011101001011110', '0111101011000110011110', '0111100010000100011110', '0111101101001010011110', '0111101101001000011110', '01111011101010100011110', '0111100011101010011110', '0111101110101000011110', '0111101010111011011110', '0111100010001011011110', '0111100101110111011110', '01111010110011101011110', '011110101110111011011110', '0111100100101011011110', '0111100010101001011110', '01111000001110101011110', '0111100101110000011110', '0111101110010111011110', '0111101100110100011110', '0111101101100000011110', '0111101101110010011110', '0111101110001011011110', '0111101011010000011110', '0111100000110110011110', '0111100111010001011110', '0111100010010011011110', '01111011101000111011110', '01111001011101101011110', '0111100111000000011110', '0111101001110101011110', '0111100001110000011110', '011110111010111010011110', '0111100001010111011110', '0111101011001000011110', '0111101100011101011110', '0111100100000010011110', '01111001110011101011110', '0111101100010110011110', '0111101100010110011110', '0111100101000011011110', '0111100001110111011110', '01111001110100001011110', '0111100000011001011110', '0111100000110111011110', '01111001110101011011110', '0111100100000001011110', '0111100001011001011110', '0111100101101110011110', '0111101001110100011110', '01111011101000100011110', '0111100100000001011110', '0111100010010011011110', '0111100110110100011110', '0111101010010011011110', '0111101000000101011110', '0111101001100110011110', '0111100100110100011110', '01111011101110101011110', '0111100100110011011110', '01111011011101000011110', '0111101000010000011110', '0111100001000101011110', '01111000001110110011110', '0111100100011011011110', '0111100111001000011110', '011110111011101010011110', '0111101100101010011110', '0111100010001000011110', '01111011101011101011110', '0111100000100011011110', '0111101100110110011110', '01111001101110101011110', '01111001110111011011110', '01111011011101110011110', '0111101101011010011110', '01111001101110111011110', '0111101101101110011110', '0111101110011010011110', '0111101001001101011110', '0111100000110110011110', '0111100010011101011110', '0111101101000101011110', '01111001110100000011110', '0111101100111001011110', '0111101100101100011110', '0111100110010010011110', '0111101000000001011110', '0111100010000110011110', '01111010110111011011110', '0111101101110010011110', '01111001110110011011110', '0111101001000110011110', '0111100010010101011110', '0111100111000000011110', '0111100001011010011110', '0111100001001000011110', '01111010101110100011110', '0111100000010101011110', '01111001110110100011110', '0111101010100001011110', '01111011101000110011110', '0111101110000011011110', '0111101110111010011110', '0111101100000010011110', '0111100011001011011110', '011110111011101000011110', '0111100001000010011110', '0111101010001110011110', '0111100000100100011110', '01111011101011011011110', '0111100010101010011110', '0111100010110011011110', '0111100011001100011110', '0111100101011000011110', '01111011101000000011110', '0111101011100010011110', '01111010101011101011110', '0111101110101101011110', '01111001110111010011110', '0111101110110000011110', '0111101000100100011110', '0111101110001010011110', '0111100101010111011110', '01111000011011101011110', '0111100110001011011110', '01111011101000111011110', '0111100000000100011110', '01111000001110110011110', '0111101110001110011110', '0111101011000000011110', '0111101001001100011110', '0111100101110101011110', '011110011101110111011110', '0111100011101110011110', '0111100100011010011110', '0111101001100111011110', '0111100100001001011110', '0111101101100110011110', '0111100011001100011110', '0111101001000101011110', '0111101110011011011110', '0111101011010101011110', '0111101110110111011110', '0111100000001101011110', '0111100011000101011110', '01111001100111010011110', '0111100110000111011110', '01111011101000010011110', '0111100000000001011110', '0111100010010101011110', '0111101100000001011110', '0111101000110000011110', '0111100010101110011110', '0111101110001110011110', '0111100011010111011110', '01111011101110100011110', '0111101100101100011110', '0111100110101001011110', '01111000001011101011110', '0111100110111011011110', '01111000111010111011110', '0111101101100101011110', '01111001110111000011110', '01111001110111011011110', '01111000010111011011110', '0111101000101000011110', '0111101010001010011110', '01111001110101100011110', '0111100100000100011110', '011110011101110100011110', '01111010111010000011110', '01111011101000100011110', '0111101110110111011110', '0111100000010001011110', '0111100001001010011110', '0111101010011100011110', '01111000111011010011110', '01111000011101010011110', '011110010111011101011110', '0111100010100010011110', '0111101011001100011110', '0111101001000010011110', '0111100001010011011110', '0111100011100100011110', '01111011101000101011110', '0111100100011011011110', '0111100011001010011110', '0111101001011011011110', '011110111010111010011110', '0111101001110011011110', '0111101100010010011110', '0111100011011010011110', '0111100110100111011110', '0111101110011010011110', '0111100000010000011110', '0111101000100110011110', '0111100000010001011110', '01111000110111010011110', '01111001100111010011110', '011110010111011101011110', '0111100010000101011110', '0111100101001100011110', '0111100011000110011110', '0111100011100101011110', '011110111011011101011110', '0111100100101101011110', '0111100001101000011110', '0111100100100011011110', '0111101010110101011110', '0111100100111000011110', '0111101001110010011110', '0111100110010001011110', '0111101101101110011110', '0111101110001110011110', '0111100000011011011110', '0111100101100110011110', '0111101011001100011110', '0111101000011101011110', '01111011001011101011110', '01111000001110101011110', '01111011101010110011110', '0111101001000001011110', '01111001110011101011110', '01111010001110100011110', '0111100001010000011110', '0111101011001000011110', '0111101100010100011110', '0111100110010100011110', '01111010110011101011110', '0111100111010101011110', '0111101000011000011110', '0111101110011010011110', '0111101110010111011110', '0111100111000010011110', '01111000100111011011110', '011110110111011101011110', '01111011001011101011110', '0111101110001100011110', '01111011101000011011110', '0111101001001100011110', '01111011010011101011110', '0111100011100010011110', '01111000101011101011110', '0111101011010111011110', '0111101011011101011110', '0111101000011011011110', '0111101101010010011110', '0111100001000011011110', '0111100101010000011110', '0111100110011011011110', '01111000110011101011110', '0111100010001001011110', '0111100011101011011110', '01111000011101000011110', '0111100011000011011110', '01111001110101011011110', '0111101000101011011110', '0111100011010000011110', '01111000011011101011110', '01111000111010110011110', '0111100110010111011110', '011110011101110111011110', '01111001110111011011110', '0111100001110111011110', '0111100110100111011110']
    # # receive = ['0111101000100010011110', '0111100001010110011110', '01111001110101011011110', '0111101010001001011110', '01111011101000111011110', '01111011101010110011110', '0111101110010100011110', '01111000110111010011110', '0111101010100000011110', '0111100110000000011110', '0111101100000000011110', '0111100111000011011110', '0111101011000101011110', '011110111011101000011110', '01111001110111010011110', '01111001001011110', '0111101011000110011110', '0111100010000100011110', '0111101101001010011110', '0111101101001000011110', '01111011101010101110011110', '0111101110101000011110', '0111101010111011011110', '0111100010001011011110', '0111100101110111011110', '01111010110011101011110', '011110101110111011011110', '0111100100101011011110', '0111100010101001011110', '01111000001110101011110', '0111100101110000011110', '0111101110010111011110', '0111101100110100011110', '0111101101100000011110', '0111101101110010011110', '0111101110001011011110', '0111101011010000011110', '0111100000110110011110', '0111100111010001011110', '0111100010010011011110', '01111011101000111011110', '01111001011101101011110', '0111100111000000011110', '0111101001110101011110', '0111101011001000011110', '0111101100011101011110', '0111100100000010011110', '01111001110011101011110', '0111101100010110011110', '0111101100010110011110', '0111100000011001011110', '0111100000110111011110', '01111001110101011011110', '0111100100000001011110', '0111100001011001011110', '0111100101101110011110', '0111101001110100011110', '01111011101000100011110', '0111100100000001011110', '0111100010010011011110', '0111100110110100011110', '0111101010010011011110', '0111101000000101011110', '0111101001100110011110', '0111100100110100011110', '01111011101110101011110', '0111100100110011011110', '01111011011101000011110', '0111101000010000011110', '0111100001000101011110', '01111000001110110011110', '0111100100011011011110', '0111100111001000011110', '011110111011101010011110', '0111101100101010011110', '0111100010001000011110', '01111011101011101011110', '0111100000100011011110', '01111000100011011110', '01111001110111011011110', '01111011011101110011110', '0111101101011010011110', '01111001101110111011110', '0111101101101110011110', '0111101110011010011110', '0111101001001000011110', '01111011110011110', '0111101101000101011110', '01111001110100000011110', '0111101100111001011110', '0111101100101100011110', '0111100110010010011110', '0111101000000001011110', '0111100010000110011110', '01111010110111011011110', '0111101101110010011110', '01111001110110011011110', '0111101001000110011110', '0111100010010101011110', '0111100111000000011110', '0111100001011010011110', '0111100001001000011110', '01111010101110100011110', '0111100000010101011110', '01111001110110100011110', '0111101010100001011110', '01111011101000110011110', '0111101110000011011110', '0111101110111010011110', '0111101100001011110', '011110111011101000011110', '0111100001000010011110', '0111101010001110011110', '0111100000100100011110', '01111011101011011011110', '0111100110110011011110', '0111100011001100011110', '0111100101011000011110', '01111011101000000011110', '0111101011100010011110', '01111010101011101011110', '0111101110101101011110', '01111001110111010011110', '0111101110110000011110', '0111101000100100011110', '0111101110001010011110', '0111100101010111011110', '01111000011011101011110', '0111100110001011011110', '01111011101000111011110', '0111100000000100011110', '01111000001110110011110', '0111101110001110011110', '0111101011000000011110', '0111101001001100011110', '0111100101110101011110', '011110011101110111011110', '0111100011101110011110', '0111100100011010011110', '0111101001100111011110', '0111100100001001011110', '0111101101100110011110', '0111100011001100011110', '01111010010000100110011110', '0111101110110111011110', '0111100000001101011110', '0111100011000101011110', '01111001100111010011110', '0111100110000111011110', '01111011101000010011110', '0111100000000001011110', '0111100010010101011110', '0111101100000001011110', '0111101000110000011110', '0111100010101110011110', '0111101110001110011110', '0111100011010111011110', '01111011101110100011110', '0111101100101100011110', '0111100110101001011110', '01111000001011101011110', '0111100110111011011110', '01111000111010111011110', '0111101101100101011110', '01111001110111000011110', '01111001110111011011110', '01111000010111011011110', '0111101000101000011110', '0111101010001010011110', '011110010100011110', '011110011101110100011110', '01111010111010000011110', '01111011101000100011110', '0111101110110111011110', '0111100000010001011110', '0111100001001010011110', '0111101010011100011110', '01111000111011010011110', '01111000011101010011110', '011110010111011101011110', '0111100001010011011110', '0111100011100100011110', '01111011101000101011110', '0111100100011011011110', '0111100011001010011110', '0111101001011011011110', '011110111010111010011110', '0111101001110011011110', '0111101100010010011110', '0111100011011010011110', '0111100110100111011110', '0111101110011010011110', '0111100000010000011110', '0111101000100110011110', '0111100000010001011110', '01111000110111010011110', '01111001100111010011110', '011110010111011101011110', '0111100010000101011110', '0111100101001100011110', '01111001100100101011110', '011110111011011101011110', '0111100100101101011110', '0111100001101000011110', '0111100100100011011110', '0111101010110101011110', '0111100100111000011110', '0111101001001011110', '0111101101101110011110', '0111101110001110011110', '0111100000011011011110', '0111100101100110011110', '0111101011001100011110', '0111101000011101011110', '01111011001011101011110', '01111000001110101011110', '01111011101010110011110', '0111101001000001011110', '01111001110011101011110', '01111010001110100011110', '0111100001010000011110', '0111101011001000011110', '0111101100010100011110', '0111100110010100011110', '01111010110011101011110', '0111100111010101011110', '0111101000011000011110', '0111101110011010011110', '0111101110010111011110', '01111011001011101011110', '0111101110001100011110', '01111011101000011011110', '0111101001001100011110', '01111011010011101011110', '0111101011011101011110', '0111101000011011011110', '0111101101010010011110', '0111100001000011011110', '0111100101010000011110', '0111100110011011011110', '01111000110011101011110', '0111100010001001011110', '0111100011101011011110', '01111000011101000011110', '0111100011000011011110', '01111001110101011011110', '0111101000101011011110', '0111100011010000011110', '01111000011011101011110', '01111000111010110011110', '0111100110010111011110', '011110011101110111011110', '01111001110111011011110', '0111100001110111011110', '0111100110100111011110']
    # match = matcher(send,receive)
    # print(match)

    # pass