
from packet_helper import getPacketTimestamp, changeTimestamp, writePcap, genKey
from scapy.all import IP, TCP, PcapReader, rdpcap, wrpcap
import hashlib

PCAP_PATH = '../../tcpdump/japan/client_out.pcap'
CLIENT_PORT = 33052

def getKeySort(pkt):
    seq = pkt[TCP].seq
    timestamp = getPacketTimestamp(pkt)[0]
    return int(str(timestamp)+str(seq))
def getKeySortTM(pkt):
    timestamp = getPacketTimestamp(pkt)[0]
    return int(timestamp)

BUFFER_SIZE = 8
def genHashNumber(num):
    return int(hashlib.sha256(str(num).encode()).hexdigest(), base=16)
def getBufferIdx(seq):
    return genHashNumber(seq) % BUFFER_SIZE

def readMessage():
    count = 1
    text=""
    serverPcap = rdpcap(PCAP_PATH)
    sessions = serverPcap.sessions()
    output = []
    session = sessions['TCP 34.84.170.196:80 > 192.168.15.85:33052']
    lastTimestamp = 0
    session.sort(key=getKeySort)
    last_seq = 0
    limit = 0
    buff = [None]* BUFFER_SIZE
    sol = []
    for pkt in session:
        if pkt[TCP].dport == CLIENT_PORT:
            timestamp = getPacketTimestamp(pkt)[0]
            seq = pkt[TCP].seq

            if lastTimestamp != timestamp and limit < timestamp  and seq!= last_seq:
                # if count >= 179 and count <= 281:
                #     print('seq:', pkt[TCP].seq, 'timestamp', timestamp, 'value', timestamp%2,'last_tm:', lastTimestamp)
                #     text+=str(timestamp%2)
                print("seq:", seq, "timestamp:", timestamp, "bit:", timestamp%2)
                output.append(timestamp%2)
                idx = getBufferIdx(seq)
                buff[idx] = timestamp%2
                print("******",len(sol)+1,"***** seq",seq,"*****","idx",idx,"******* bit:",timestamp%2)
                if idx == 0 and timestamp%2 == 1:
                    sol.append(buff[1:])
                    buff = [None]* BUFFER_SIZE
                lastTimestamp = timestamp
                limit = max(limit, timestamp)
            last_seq = seq

    finale = ""
    for i in output:
        finale = finale + str(i)
    # print(finale)
    # print(text)
    # print("final")
    # print(finale)
    print(sol)
    return finale

if __name__ == '__main__':
    readMessage()