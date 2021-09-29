
from packet_helper import getPacketTimestamp
from scapy.all import TCP, rdpcap

PCAP_PATH = '../../tcpdump/japan/client_out.pcap'
CLIENT_PORT = 33052

def getKeySort(pkt):
    seq = pkt[TCP].seq
    timestamp = getPacketTimestamp(pkt)[0]
    return int(str(seq)+str(timestamp))

    


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
    for pkt in session:
        if pkt[TCP].dport == CLIENT_PORT:
            timestamp = getPacketTimestamp(pkt)[0]
            seq = pkt[TCP].seq

            if lastTimestamp != timestamp and limit < timestamp  and seq!= last_seq:
                # if count >= 179 and count <= 281:
                #     print('seq:', pkt[TCP].seq, 'timestamp', timestamp, 'value', timestamp%2,'last_tm:', lastTimestamp)
                #     text+=str(timestamp%2)
                output.append(timestamp%2)
                count += 1
                lastTimestamp = timestamp
                limit = max(limit, timestamp)
            last_seq = seq

    finale = ""
    for i in output:
        finale = finale + str(i)

    return finale

if __name__ == '__main__':
    readMessage()