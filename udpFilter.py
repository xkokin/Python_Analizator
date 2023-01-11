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


# class ktory obsahuje polozky pre packet a ho poriadove cislo v pcap subore
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
    port_x = str()
    port_y = str()
    complete = bool()
    finished = bool()

    def set_ports(self, x, y):
        self.port_x = x
        self.port_y = y

    def set_port_y(self, y):
        self.port_y = y

    def get_port_x(self):
        return self.port_x

    def get_port_y(self):
        return self.port_y

    def set_finished(self, b):
        self.finished = b

    def is_finished(self):
        return self.finished

    def is_complete(self):
        return self.complete

    def get_comm_packets(self):
        return self.comm_packets

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

    def add_comm_pack(self, p, i):
        temp = num_pack(p, i)
        self.comm_packets.append(temp)

    def __init__(self, src, dst, x, y, b):
        self.comm_packets = []
        self.set_adress(src, dst)
        self.set_ports(x, y)
        self.set_finished(b)
        self.set_complete()


def check_packet(p):
    # je request
    if hexlify(raw(p)).decode()[84:88] == '0001':
        return 1
    # je data packet alebo acknoledgment
    elif hexlify(raw(p)).decode()[84:88] == '0003' or hexlify(raw(p)).decode()[84:88] == '0004':
        return 3
    # je session termination
    elif hexlify(raw(p)).decode()[84:88] == '0005':
        return 2


def print_filtered_tftp(pcap_name, prot):
    comms = []
    tabu = '    '
    cycle = [1, 2]
    packets = rdpcap("pcapy/" + pcap_name)  # trace 15
    h = open("vystup_udp.yaml", "w")
    h.write("name: PKS2022/23\npcap_name: " + pcap_name + '\n')
    h.write("filter_name: TFTP\n")

    cnt_pack = 1
    # najprv odlozime vsetky potrebne tftp packety
    for pack in packets:
        if int(hexlify(raw(pack)).decode()[24:28], 16) >= 1536:
            if prot + "\n" == getType(str(int(hexlify(raw(pack)).decode()[68:72], 16)), 4) \
                    or prot + "\n" == getType(str(int(hexlify(raw(pack)).decode()[72:76], 16)), 4):
                # ak mame tftp packet ktory otvara komunikaciu tak vytvorime novy objekt komunikacii
                if check_packet(pack) == 1:
                    temp = comm(str(getIP(hexlify(raw(pack)).decode()[52:60])),
                                str(getIP(hexlify(raw(pack)).decode()[60:68])),
                                str(int(hexlify(raw(pack)).decode()[68:72], 16)),
                                str(int(hexlify(raw(pack)).decode()[72:76], 16)), False)  # zapisuje v policko port_y 69
                    temp.add_comm_pack(pack, cnt_pack)
                    comms.append(temp)
            # ak ziadny port neobsahuje tftp hodnotu tak tento packet moze byt stale tftp
            else:
                added = 0
                for c in comms:
                    # overime podobnost adries
                    if (c.get_src_adress() == getIP(hexlify(raw(pack)).decode()[52:60])
                        and c.get_dst_adress() == getIP(hexlify(raw(pack)).decode()[60:68])
                        and c.is_finished() is False) or \
                            (c.get_src_adress() == getIP(hexlify(raw(pack)).decode()[60:68])
                             and c.get_dst_adress() == getIP(hexlify(raw(pack)).decode()[52:60])
                             and c.is_finished() is False):
                        # ak oni nam vyhovuju tak overime hodnoty portov
                        # oni musia byt vymenene miestami
                        if (str(int(hexlify(raw(pack)).decode()[68:72], 16)) == c.get_port_x() and
                            str(int(hexlify(raw(pack)).decode()[72:76], 16)) == c.get_port_y()) or \
                                (str(int(hexlify(raw(pack)).decode()[68:72], 16)) == c.get_port_y() and
                                 str(int(hexlify(raw(pack)).decode()[72:76], 16)) == c.get_port_x()):

                            if check_packet(pack) == 3:
                                c.add_comm_pack(pack, cnt_pack)
                            # ak najdeme Error code tak uzatvorime komunikaciu
                            if check_packet(pack) == 2:
                                c.add_comm_pack(pack, cnt_pack)
                                c.set_finished(True)

                            added = 1
                            break
                        else:
                            if c.get_port_y() == "69" and \
                                    c.get_port_x() == str(int(hexlify(raw(pack)).decode()[72:76], 16)):
                                c.set_port_y(str(int(hexlify(raw(pack)).decode()[68:72], 16)))
                                if check_packet(pack) == 3:
                                    c.add_comm_pack(pack, cnt_pack)
                                if check_packet(pack) == 2:
                                    c.add_comm_pack(pack, cnt_pack)
                                    c.set_finished(True)


                if added == 1:
                    cnt_pack += 1
                    continue
        cnt_pack += 1

    for i in cycle:
        if len(cycle) == 2 and i == 1:
            h.write("complete_comms:\n")
        elif len(cycle) == 2 and i == 2:
            h.write("partial_comms:\n")

        cnt_comm = 1
        #vypis funguje tak isto ako pri standartnom vypise vsetkych ramcov
        for c in comms:
            counter = 1
            if c.is_complete() is False and i == 1:
                continue
            if c.is_complete() is True and i == 2:
                continue

            h.write("  - number_comm: " + str(cnt_comm) + "\n")
            if i == 1:
                h.write(tabu + "src_comm: " + c.get_src_adress() + "\n" +
                        tabu + "dst_comm: " + c.get_dst_adress() + "\n")
            h.write(tabu + "packets:\n")

            for packet in c.get_comm_packets():
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
                src_ip = getIP(hexlify(raw(packet.get_pack())).decode()[52:60])
                dst_ip = getIP(hexlify(raw(packet.get_pack())).decode()[60:68])

                # vypis mac adresov
                h.write(tabu + "    src_mac: " + getMAC(hexlify(raw(packet.get_pack())).decode()[12:24]) + "\n")
                h.write(tabu + "    dst_mac: " + getMAC(hexlify(raw(packet.get_pack())).decode()[0:12]) + "\n")

                # riesenie roznych protocolov ethernetu 2
                if ethertype == "":
                    h.write(tabu + "    ether_type: unknown\n")
                elif ethertype != "":
                    h.write(tabu + "    ether_type: " + ethertype)
                if ethertype == 'IPv4\n':
                    h.write(tabu + "    src_ip: " + src_ip + '\n')
                    h.write(tabu + "    dst_ip: " + dst_ip + '\n')
                    protocol = getType(hexlify(raw(packet.get_pack())).decode()[46:48], 2)
                    h.write(tabu + "    protocol: " + protocol)
                    h.write(tabu + "    src_port: " + str(int(hexlify(raw(packet.get_pack())).decode()[68:72], 16)) + '\n')
                    h.write(tabu + "    dst_port: " + str(int(hexlify(raw(packet.get_pack())).decode()[72:76], 16)) + '\n')

                    h.write(tabu + "    app_protocol: TFTP\n")

                    if hexlify(raw(packet.get_pack())).decode()[84:88] == '0001':
                        h.write(tabu + "    tftp_opcode: READ REQUEST\n")
                    elif hexlify(raw(packet.get_pack())).decode()[84:88] == '0005':
                        h.write(tabu + "    tftp_opcode: ERROR\n")
                    elif hexlify(raw(packet.get_pack())).decode()[84:88] == '0003':
                        h.write(tabu + "    tftp_opcode: DATA PACKET\n")
                    elif hexlify(raw(packet.get_pack())).decode()[84:88] == '0004':
                        h.write(tabu + "    tftp_opcode: ACKNOWLEDGMENT\n")

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
    print_filtered_tftp(args[0], "TFTP")


if __name__ == '__main__':
    main()
