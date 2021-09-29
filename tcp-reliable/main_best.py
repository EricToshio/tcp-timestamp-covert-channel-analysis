from injector import Injector
from packet_helper import getPacketTimestamp, changeTimestamp, writePcap, genKey
import math
from scapy.all import TCP, rdpcap

CLIENT_PCAP_PATH = '../../tcpdump/japan/client_only.pcap'
CLIENT_PCAP_OUT_PATH = '../../tcpdump/japan/client_out.pcap'
SERVER_PCAP_PATH = '../../tcpdump/japan/server_only.pcap'
SERVER_PCAP_OUT_PATH = '../../tcpdump/japan/server_out.pcap'

SERVER_PORT = 80
CLIENT_PORT = 33052


def getLoad(pkt):
    try:
        return len(pkt[TCP].load)
    except:
        return 0

"""
Server will send modified packet to client!
1) Analysis server pcap to find packets that should be modified
2) Change same packet in client pcap
"""

def modifyPktsTimestamp(timestamp, pkt, pktRelation, clientPkts, clientKeyPkt):
    key = genKey(pkt)
    changeTimestamp(pkt, timestamp)
    for clientKey in pktRelation[key]:
        idx = clientKeyPkt[clientKey]
        changeTimestamp(clientPkts[idx], timestamp)
    
def insertMessage():
    print('Start loading server pcap:')
    serverPkts = rdpcap(SERVER_PCAP_PATH)
    print('success read server pcap!')

    print('Start loading client pcap:')
    clientPkts = rdpcap(CLIENT_PCAP_PATH)
    print('success read client pcap!')

    # Create map for unique key to pkt

    serverKeyPkt = {}
    for idx in range(len(serverPkts)):
        pkt = serverPkts[idx]
        if pkt[TCP].dport == CLIENT_PORT:
            key = genKey(pkt)
            if key in serverKeyPkt:
                print(pkt[TCP].seq)
                raise ValueError('Server has duplicated key')
            serverKeyPkt[key] = idx

    clientKeyPkt = {}
    for idx in range(len(clientPkts)):
        pkt = clientPkts[idx]
        if pkt[TCP].dport == CLIENT_PORT:
            key = genKey(pkt)
            if key in clientKeyPkt:
                raise ValueError('Client has duplicated key')
            clientKeyPkt[key] = idx
    

    # Find related timestamp packets

    ## Order sequence number
    seqNumbers = list(set(map(lambda pkt: pkt[TCP].seq, serverPkts)))
    seqNumbers.sort()

    ## Find relations
    timestampRelation = {}
    for idx in range(len(serverPkts)):
        pkt = serverPkts[idx]
        if pkt[TCP].dport == CLIENT_PORT:
            seq = pkt[TCP].seq
            timestamp, _ = getPacketTimestamp(pkt)

            # Get next seq number
            next_seq = math.inf
            seqIdx = seqNumbers.index(seq)
            if seqIdx + 1 < len(seqNumbers):
                next_seq = seqNumbers[seqIdx + 1]

            value = { 'end_seq': next_seq, 'ini_seq': seq, 'src_pkt': genKey(pkt), 'dst_pkt':[]}
            if timestamp in timestampRelation:
                timestampRelation[timestamp].append(value)
            else:
                timestampRelation[timestamp] = [value]

    for idx in range(len(clientPkts)):
        pkt = clientPkts[idx]
        if pkt[TCP].dport == CLIENT_PORT:
            seq = pkt[TCP].seq
            timestamp, _ = getPacketTimestamp(pkt)

            if timestamp in timestampRelation:
                for value in timestampRelation[timestamp]:
                    if seq >= value['ini_seq'] and seq < value['end_seq']:
                        value['dst_pkt'].append(genKey(pkt))

    pktRelation = {}
    for timestamp in timestampRelation:
        relationArray = timestampRelation[timestamp]
        for relation in relationArray:
            pktRelation[relation['src_pkt']] = relation['dst_pkt']


    # Insert secret message
    insert = Injector()
    counter = 0

    last_seq = 0
    for idx in range(len(serverPkts)):
        pkt = serverPkts[idx]
        seq = pkt[TCP].seq

        if pkt[TCP].dport == CLIENT_PORT:
            seq = pkt[TCP].seq
            # if seq <= last_seq:
            #     continue
            timestamp, _ = getPacketTimestamp(pkt)
            change, new_timestamp = insert.timestamp(timestamp, seq, getLoad(pkt))
            if change:
                counter += 1
                modifyPktsTimestamp(new_timestamp, pkt, pktRelation, clientPkts,clientKeyPkt)
            last_seq = max(seq, last_seq)
        else:
            # print("ack",pkt[TCP].ack)
            insert.ackPkt(pkt[TCP].ack)

    print('Modified %:', 100*(counter/len(serverPkts)))
    

    # Create a output pcap with modified timestamp
    writePcap(serverPkts, SERVER_PCAP_OUT_PATH)
    writePcap(clientPkts, CLIENT_PCAP_OUT_PATH)

    # #print(insert.sentData)
    # messages = []
    # for i in insert.allSecrets:
    #     m = ""
    #     for j in i:
    #         m = m + str(j)
    #     messages.append(m)
    # return messages
    print(insert.allSecrets)


if __name__ == '__main__':
    insertMessage()