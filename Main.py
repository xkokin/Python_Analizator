from scapy.all import *
from binascii import *
from arpFilter import print_filtered_arp
from udpFilter import print_filtered_tftp


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

# class urceny pre ipv4 sendera
# ma pocitadlo odoslanych paketov
class sender:
    adress = str()
    packs = int()

    def setSender(self, adress):
        self.adress = adress
        self.packs = 1

    def getSender(self):
        return self.adress

    def getPacks(self):
        return self.packs

    def sent(self):
        self.packs += 1

#funkcia vypisuje vsetky ramce
def printPackets(pcap_name):
    global type
    global ethertype
    senders = []

    packets = rdpcap("pcapy/" + pcap_name)

    f = open("vystup.yaml", "w")
    f.write("name: PKS2022/23\npcap_name: " + pcap_name + "\n")

    f.write("packets:\n")

    counter = 1
    for packet in packets:
        # vypis poriadoveho cisla ramca, dlzku pcapu a delzku media
        if packet.wirelen < 60:
            temp = 64
        else:
            temp = packet.wirelen + 4
        f.write("  - frame_number: " + str(counter) + "\n")
        f.write("    len_frame_pcap: " + str(packet.wirelen) + "\n")
        f.write("    len_frame_medium: " + str(temp) + "\n")

        # urcenie typu ramca
        if int(hexlify(raw(packet)).decode()[24:28], 16) >= 1536:
            type = 'e'
            f.write("    frame_type: " + "ETHERNET II" + "\n")
            # urcime presny protokol sietovej vrstvy
            ethertype = getType(hexlify(raw(packet)).decode()[24:28].upper(), 1)

        elif int(hexlify(raw(packet)).decode()[24:28], 16) <= 1500:
            if hexlify(raw(packet)).decode()[28:32] == 'aaaa':
                type = 's'
                # ak mame Snap - urcime snap PID
                snap = getType(hexlify(raw(packet)).decode()[40:44].upper(), 6)
                f.write("    frame_type: " + "IEEE 802.3 LLC & SNAP" + "\n")
            elif hexlify(raw(packet)).decode()[28:32] == 'ffff':
                type = 'r'
                f.write("    frame_type: " + "IEEE 802.3 RAW" + "\n")
            else:
                type = 'l'
                f.write("    frame_type: " + "IEEE 802.3 LLC" + "\n")
                # ak mame llc - urcime SAP
                sap = getType(hexlify(raw(packet)).decode()[28:30].upper(), 3)
        # vypis mac adresov
        f.write("    src_mac: " + getMAC(hexlify(raw(packet)).decode()[12:24]) + "\n")
        f.write("    dst_mac: " + getMAC(hexlify(raw(packet)).decode()[0:12]) + "\n")

        if type == 'e':
            # riesenie roznych protokolov ethernetu 2
            if ethertype == "":
                f.write("    ether_type: unknown\n")
            elif ethertype != "":
                f.write("    ether_type: " + ethertype)
            if ethertype == 'IPv4\n':
                # ak mame IPv4 tak urcime presny protokol transportnej vrstvy
                protocol = getType(hexlify(raw(packet)).decode()[46:48], 2)
                # zapiseme sender ip pre buduci zoznam senderov
                src_ip = getIP(hexlify(raw(packet)).decode()[52:60])

                found = 0
                for pck_sender in senders:
                    # ak mame sendera ktory uz bol zaznamenany tak inkrementujeme pocitadlo odoslanych paketov
                    if pck_sender.getSender() == src_ip:
                        pck_sender.sent()
                        found = 1
                # inak vytvorime noveho sendera a priradime mu 1 odoslany packet
                if found == 0:
                    new_sender = sender()
                    new_sender.setSender(src_ip)
                    senders.append(new_sender)

                f.write("    src_ip: " + src_ip + '\n')
                f.write("    dst_ip: " + getIP(hexlify(raw(packet)).decode()[60:68]) + '\n')
                f.write("    protocol: " + protocol)
                # ak mame UDP alebo TCP protokol tak skusime najst znamy port
                # a vypiseme ho ako protokol aplikacnej vrstvy
                if protocol == 'UDP\n' or protocol == 'TCP\n':
                    uts = getType(str(int(hexlify(raw(packet)).decode()[68:72], 16)), 4)
                    utd = getType(str(int(hexlify(raw(packet)).decode()[72:76], 16)), 4)
                    f.write("    src_port: " + str(int(hexlify(raw(packet)).decode()[68:72], 16)) + '\n')
                    f.write("    dst_port: " + str(int(hexlify(raw(packet)).decode()[72:76], 16)) + '\n')
                    if uts != "":
                        f.write("    app_protocol: " + uts)
                    elif utd != "":
                        f.write("    app_protocol: " + utd)

            elif ethertype == 'ARP\n':
                # ak pracujeme z protokolom ARP tak urcime typ odoslanej spravy
                if hexlify(raw(packet)).decode()[40:44] == '0001':
                    f.write("    arp_opcode: REQUEST\n")
                elif hexlify(raw(packet)).decode()[40:44] == '0002':
                    f.write("    arp_opcode: REPLY\n")
                f.write("    src_ip: " + getIP(hexlify(raw(packet)).decode()[56:64]) + '\n')
                f.write("    dst_ip: " + getIP(hexlify(raw(packet)).decode()[76:84]) + '\n')
        # riesenie sapov LLC
        if type == 'l':
            f.write("    sap: " + sap)
        # risenie snapov
        elif type == 's':
            f.write("    pid: " + snap)

        frame = (hexlify(raw(packet)).decode()).upper()
        f.write("    hexa_frame: |\n      ")

        # formatovanie a vypis ramcu v hexadecimalnom tvare
        cnt = 0
        temp = ''
        for el in frame:
            temp += el
            cnt += 1
            if (cnt % 32) == 0:
                temp += "\n      "
            elif (cnt % 2) == 0:
                if len(frame) != cnt:
                    temp += frame[len(temp):cnt] + " "

        f.write(temp)
        # print(temp)
        f.write("\n")
        counter += 1

    # vypis senderov ipv4
    max_senders = []
    f.write("\nipv4_senders:")
    for pck_s in senders:
        f.write("\n  - node: " + pck_s.getSender() +
                "\n    number_of_sent_packets: " + str(pck_s.getPacks()) + "\n")
        if len(max_senders) == 0 or pck_s.getPacks() == max_senders[0].getPacks():
            max_senders.append(pck_s)
        elif pck_s.getPacks() > max_senders[0].getPacks():
            max_senders.clear()
            max_senders.append(pck_s)

    f.write("\nmax_send_packets_by:\n")
    for pck_sender in max_senders:
        f.write("  - " + pck_sender.getSender() + "\n")

    f.close()


def main():
    args = sys.argv[1:]
    print("Printing all packets into the vystup.yaml has been started")
    printPackets(args[0])
    print("Printing all packets into the vystup.yaml has been finished")

    if len(args) >= 2 and args[1] == '-p':
        if len(args) >= 2:
            typo = getType(args[2], 5)
        else:
            typo = ""
        if typo == "":
            print("The protocol you are trying to filter is incorrect.\nPlease, try again.")
            return 1
        elif typo == '80\n' or typo == '443\n' or typo == '20\n' or typo == '21\n' or typo == '22\n' or typo == '23\n':
            # print_filtered_tcp(args[1])
            print("TCP packets are currently unavailable for filtering")
        elif typo == "2054\n":
            print("Filtering by ARP into the vystup_arp.yaml has been started")
            print_filtered_arp(args[0], "ARP")
            print("Filtering by ARP into the vystup_arp.yaml has been finished")
        elif typo == "69\n":
            print("Filtering by TFTP into the vystup_udp.yaml has been started")
            print_filtered_tftp(args[0], "TFTP")
            print("Filtering by TFTP into the vystup_udp.yaml has been finished")


if __name__ == '__main__':
    main()
