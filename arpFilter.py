from scapy.all import *
from binascii import *


def getType(num, typ):
    # ak typ == 1 hladame Ether type
    # ak typ == 2 hladame IP typ
    # ak typ == 3 hladame SAP typ
    # ak typ == 4 hladame UDP&TCP ports
    # ak typ == 5 hladame protokoly prepinaca
    # ak typ == 6 hladame SNAP PID

    match typ:
        case 1:
            stri = '#ethertypes\n'
        case 2:
            stri = '#IP Protocol numbers\n'
        case 3:
            stri = '#LSAPs\n'
        case 4:
            stri = '#UDP&TCP ports\n'
        case 5:
            stri = '#-p\n'
        case 6:
            stri = '#SNAP PID\n'

    k = open("protocols.txt", "r")

    # v cycle citame subor z protokolmy, ked ne narazime na nutny protokol alebo koniec suboru
    while True:
        line = k.readline()
        if line:
            if line == stri:
                line = k.readline()
                while line[0] != '#':
                    if num == line[0:len(num)]:
                        k.close()
                        # ked sme nasli nutni protokol tak vratime ho
                        return line[len(num) + 1:len(line)]
                    else:
                        line = k.readline()
                        if line == "":
                            break
        elif not line:
            break
    k.close()
    # ak protokol ne bol najdeny tak vratime prazdny retazec
    return ""


def getMAC(starter):
    # prepisujeme mac adresu vo vhodny tvar
    res = starter[0:2].upper() + ":" + starter[2:4].upper() + ":" + starter[4:6].upper() \
          + ":" + starter[6:8].upper() + ":"
    res += starter[8:10].upper() + ":" + starter[10:12].upper()
    return res


def getIP(starter):
    # prepisujeme ip adresu na vhodny tvar
    res = str(int(starter[0:2], 16)) + "." + str(int(starter[2:4], 16)) + "." + \
          str(int(starter[4:6], 16)) + "." + str(int(starter[6:8], 16))
    return res


class num_pack:
    pack = str()
    num = int()

    def __init__(self, p, n):
        self.set_pack(p)
        self.set_num(n)

    def set_pack(self, p):
        self.pack = p

    def set_num(self, n):
        self.num = n

    def get_num(self):
        return self.num

    def get_pack(self):
        return self.pack


class comm:
    src_ad = str()
    dst_ad = str()
    complete = bool()
    finished = bool()

    def set_comm_pack_fin(self):
        c = 0
        while len(self.comm_packets_fin) != len(self.comm_packets_open) + len(self.comm_packets_close):
            if len(self.comm_packets_open) >= c + 1:
                self.comm_packets_fin.append(self.comm_packets_open[c])
            if len(self.comm_packets_close) >= c + 1:
                self.comm_packets_fin.append(self.comm_packets_close[c])
            c += 1

    def get_comm_pack_fin(self):
        return self.comm_packets_fin

    def set_finished(self, b):
        self.finished = b

    def is_finished(self):
        return self.finished

    def is_complete(self):
        return self.complete

    def get_comm_packets_open(self):
        return self.comm_packets_open

    def get_comm_packets_close(self):
        return self.comm_packets_close

    def get_src_adress(self):
        return self.src_ad

    def get_dst_adress(self):
        return self.dst_ad

    def set_adress(self, src_ad, dst_ad):
        self.src_ad = src_ad
        self.dst_ad = dst_ad

    def set_complete(self):
        self.complete = True

    def set_partial(self):
        self.complete = False

    def add_comm_pack_open(self, p, i):
        temp = num_pack(p, i)
        self.comm_packets_open.append(temp)

    def add_comm_pack_close(self, p, i):
        temp = num_pack(p, i)
        self.comm_packets_close.append(temp)

    def __init__(self, src, dst, b):
        self.comm_packets_fin = []
        self.comm_packets_open = []
        self.comm_packets_close = []
        self.set_adress(src, dst)
        self.set_finished(b)


def check_packet(p):
    # je request
    if hexlify(raw(p)).decode()[40:44] == '0001':
        return 1
    # je reply
    elif hexlify(raw(p)).decode()[40:44] == '0002':
        return 2


def print_filtered_arp(pcap_name, prot):
    comms = []
    tabu = '    '
    cycle = [1, 2]
    packets = rdpcap("pcapy/" + pcap_name)
    h = open("vystup_arp.yaml", "w")
    h.write("name: PKS2022/23\npcap_name: " + pcap_name + '\n')
    h.write("filter_name: ARP\n")

    cnt_pack = 1
    for pack in packets:
        if int(hexlify(raw(pack)).decode()[24:28], 16) >= 1536:
            if prot + "\n" == getType(hexlify(raw(pack)).decode()[24:28], 1):
                added = 0
                for c in comms:
                    # ak mame packet z komunikacii ktora este nie je uzatvorena tak zapiseme tam nas packet
                    if c.get_src_adress() == getIP(hexlify(raw(pack)).decode()[56:64]) \
                            and c.get_dst_adress() == getIP(hexlify(raw(pack)).decode()[76:84]) \
                            and c.is_finished() is False:
                        if check_packet(pack) == 1:
                            c.add_comm_pack_open(pack, cnt_pack)
                        # ak zaznamenane replies je vacsie ako requesty tak popneme posledny reply
                        # a nastavime ho ku novej nekomplektnej komunikacie
                        if len(c.get_comm_packets_close()) > len(c.get_comm_packets_open()):
                            temp1 = comm(str(getIP(hexlify(raw(pack)).decode()[56:64])),
                                         str(getIP(hexlify(raw(pack)).decode()[76:84])), True)
                            temp1.add_comm_pack_close(c.get_comm_packets_close()[1], cnt_pack)
                            c.get_comm_packets_close().pop(1)
                            temp1.set_partial()
                            temp1.set_comm_pack_fin()
                            comms.append(temp1)
                        # ak pocet requestov je rovnaky alebo vacsi a pocet reply je 2
                        # tak vytvorime novu komunikaciu a prehodime poslednu par request reply tam
                        # a ten packet co sme mali nastavime na komplektny
                        elif len(c.get_comm_packets_open()) >= len(c.get_comm_packets_close()) == 2:
                            temp2 = comm(str(getIP(hexlify(raw(pack)).decode()[56:64])),
                                         str(getIP(hexlify(raw(pack)).decode()[76:84])), False)
                            temp2.add_comm_pack_open(c.get_comm_packets_open()[1], cnt_pack)
                            c.get_comm_packets_open().pop(1)
                            temp2.add_comm_pack_close(c.get_comm_packets_close()[1], cnt_pack)
                            c.get_comm_packets_close().pop(1)
                            c.set_complete()
                            c.set_finished(True)
                            c.set_comm_pack_fin()
                            comms.append(temp2)
                        added = 1
                        break
                    # spravime to iste ak adresy su vymenene miestami
                    elif c.get_src_adress() == getIP(hexlify(raw(pack)).decode()[76:84]) \
                            and c.get_dst_adress() == getIP(hexlify(raw(pack)).decode()[56:64]) \
                            and c.is_finished() is False:
                        if check_packet(pack) == 2:
                            c.add_comm_pack_close(pack, cnt_pack)
                            if len(c.get_comm_packets_close()) == len(c.get_comm_packets_open()) == 1:
                                c.set_complete()
                                c.set_finished(True)
                                c.set_comm_pack_fin()
                        if len(c.get_comm_packets_close()) > len(c.get_comm_packets_open()):
                            temp1 = comm(str(getIP(hexlify(raw(pack)).decode()[56:64])),
                                         str(getIP(hexlify(raw(pack)).decode()[76:84])), True)
                            temp1.add_comm_pack_close(c.get_comm_packets_close()[1], cnt_pack)
                            c.get_comm_packets_close().pop(1)
                            temp1.set_partial()
                            temp1.set_comm_pack_fin()
                            comms.append(temp1)
                        elif len(c.get_comm_packets_open()) >= len(c.get_comm_packets_close()) == 2:
                            temp2 = comm(str(getIP(hexlify(raw(pack)).decode()[56:64])),
                                         str(getIP(hexlify(raw(pack)).decode()[76:84])), False)
                            temp2.add_comm_pack_open(c.get_comm_packets_open()[1], cnt_pack)
                            c.get_comm_packets_open().pop(1)
                            temp2.add_comm_pack_close(c.get_comm_packets_close()[1], cnt_pack)
                            c.get_comm_packets_close().pop(1)
                            c.set_complete()
                            c.set_finished(True)
                            c.set_comm_pack_fin()
                            comms.append(temp2)
                        added = 1
                        break

                if added == 1:
                    cnt_pack += 1
                    continue
                temp = comm(str(getIP(hexlify(raw(pack)).decode()[56:64])),
                            str(getIP(hexlify(raw(pack)).decode()[76:84])), False)
                if check_packet(pack) == 1:
                    temp.add_comm_pack_open(pack, cnt_pack)
                elif check_packet(pack) == 2:
                    temp.add_comm_pack_close(pack, cnt_pack)
                comms.append(temp)
        cnt_pack += 1

    for i in cycle:
        if len(cycle) == 2 and i == 1:
            h.write("complete_comms:\n")
        elif len(cycle) == 2 and i == 2:
            h.write("partial_comms:\n")

        cnt_comm = 1
        for c in comms:
            counter = 1
            if len(c.get_comm_pack_fin()) == 0:
                c.set_comm_pack_fin()
            if c.is_complete() is False and i == 1:
                continue
            if c.is_complete() is True and i == 2:
                continue

            h.write("  - number_comm: " + str(cnt_comm) + "\n")
            if i == 1:
                h.write(tabu + "src_comm: " + c.get_src_adress() + "\n" +
                        tabu + "dst_comm: " + c.get_dst_adress() + "\n")
            h.write(tabu + "packets:\n")

            for packet in c.get_comm_pack_fin():
                # vypis poriadoveho cisla ramca a dlzku pcapu i media
                if packet.get_pack().wirelen < 60:
                    temp = 64
                else:
                    temp = packet.get_pack().wirelen + 4
                h.write(tabu + "  - frame_number: " + str(packet.get_num()) + "\n")
                h.write(tabu + "    len_frame_pcap: " + str(packet.get_pack().wirelen) + "\n")
                h.write(tabu + "    len_frame_medium: " + str(temp) + "\n")

                # urcenie typu ramca

                h.write(tabu + "    frame_type: " + "ETHERNET II" + "\n")
                ethertype = getType(hexlify(raw(packet.get_pack())).decode()[24:28].upper(), 1)
                src_ip = hexlify(raw(packet.get_pack())).decode()[53:61]
                dst_ip = hexlify(raw(packet.get_pack())).decode()[61:69]

                # vypis mac adresov
                h.write(tabu + "    src_mac: " + getMAC(hexlify(raw(packet.get_pack())).decode()[12:24]) + "\n")
                h.write(tabu + "    dst_mac: " + getMAC(hexlify(raw(packet.get_pack())).decode()[0:12]) + "\n")

                # riesenie roznych protocolov ethernetu 2
                if ethertype == "":
                    h.write(tabu + "    ether_type: unknown\n")
                elif ethertype != "":
                    h.write(tabu + "    ether_type: " + ethertype)
                if ethertype == 'ARP\n':
                    if hexlify(raw(packet.get_pack())).decode()[40:44] == '0001':
                        h.write(tabu + "    arp_opcode: REQUEST\n")
                    elif hexlify(raw(packet.get_pack())).decode()[40:44] == '0002':
                        h.write(tabu + "    arp_opcode: REPLY\n")
                    h.write(tabu + "    src_ip: " + getIP(hexlify(raw(packet.get_pack())).decode()[56:64]) + '\n')
                    h.write(tabu + "    dst_ip: " + getIP(hexlify(raw(packet.get_pack())).decode()[76:84]) + '\n')

                frame = (hexlify(raw(packet.get_pack())).decode()).upper()
                h.write(tabu + "    hexa_frame: |\n      " + tabu)

                # formatovanie a vypis ramcu v hexadecimalnom tvare
                cnt = 0
                temp = ''
                for el in frame:
                    temp += el
                    cnt += 1
                    if (cnt % 32) == 0:
                        temp += "\n" + tabu + "      "
                    elif (cnt % 2) == 0:
                        if len(frame) != cnt:
                            temp += frame[len(temp):cnt] + " "

                h.write(temp)
                # print(temp)
                h.write("\n\n")
                counter += 1
            cnt_comm += 1


def main():
    args = sys.argv[1:]
    print_filtered_arp(args[0], "ARP")


if __name__ == '__main__':
    main()
