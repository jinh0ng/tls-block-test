#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "ip.h"

void usage()
{
    printf("syntax : tls-block <interface> <server name>\n");
    printf("sample : tls-block wlan0 naver.com\n");
}

#pragma pack(push, 1)
struct PacketInfo
{
    EthHdr ethHdr_;
    IpHdr ipHdr_;
    TcpHdr tcpHdr_;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ChecksumHdr
{
    uint32_t srcAddr;
    uint32_t dstAddr;
    uint8_t reserved;
    uint8_t proto;
    uint16_t tcpLen;
};
#pragma pack(pop)

typedef struct
{
    Mac mac;
    Ip ip;
} t_info;

static t_info MyInfo;

// ---- 재조립 로직 추가 ----
struct FlowId
{
    Ip clientIp;
    Ip serverIp;
    uint16_t clientPort;
    uint16_t serverPort;
    bool operator==(FlowId const &o) const
    {
        return clientIp == o.clientIp && serverIp == o.serverIp && clientPort == o.clientPort && serverPort == o.serverPort;
    }
};

namespace std
{
    template <>
    struct hash<FlowId>
    {
        size_t operator()(FlowId const &f) const noexcept
        {
            uint64_t a = (uint64_t)f.clientIp << 32 | uint32_t(f.serverIp);
            uint64_t b = (uint64_t)f.clientPort << 16 | f.serverPort;
            return hash<uint64_t>()(a) ^ hash<uint64_t>()(b);
        }
    };
}

static std::unordered_map<FlowId, std::vector<uint8_t>> tlsReassembly;

// 기존 함수들 유지
int getMyInfo(t_info *info, const char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // MAC address
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
    {
        info->mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
    }
    else
    {
        close(fd);
        return -1;
    }

    // IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) == 0)
    {
        uint32_t raw = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
        info->ip = Ip(raw);
    }
    else
    {
        close(fd);
        return -1;
    }

    printf("My MAC: %s\n", std::string(info->mac).c_str());
    printf("My IP: %s\n", std::string(info->ip).c_str());
    close(fd);
    return 0;
}

uint16_t CheckSum(uint16_t *buffer, int size)
{
    uint32_t checksum = 0;
    while (size > 1)
    {
        checksum += *buffer++;
        size -= 2;
    }
    if (size > 0)
    {
        checksum += *(uint8_t *)buffer;
    }
    while (checksum >> 16)
    {
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    return (uint16_t)(~checksum);
}

bool parseTlsSni(const uint8_t *data, uint32_t len, std::string &sni)
{
    // 기존 파싱 로직 그대로
    if (len < 5)
        return false;
    uint32_t pos = 0;
    uint8_t type = data[pos++];
    if (type != 22)
        return false;
    pos += 2;
    uint16_t recLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    if (recLen + 5 > len)
        return false;
    if (data[pos++] != 1)
        return false;
    uint32_t hsLen = (data[pos] << 16) | (data[pos + 1] << 8) | data[pos + 2];
    pos += 3;
    if (hsLen + 4 > recLen)
        return false;
    pos += 2 + 32;
    if (pos + 1 > len)
        return false;
    uint8_t sidLen = data[pos++];
    pos += sidLen;
    if (pos + 2 > len)
        return false;
    uint16_t csLen = (data[pos] << 8) | data[pos + 1];
    pos += 2 + csLen;
    if (pos + 1 > len)
        return false;
    uint8_t compLen = data[pos++];
    pos += compLen;
    if (pos + 2 > len)
        return false;
    uint16_t extLen = (data[pos] << 8) | data[pos + 1];
    pos += 2;
    uint32_t extEnd = pos + extLen;
    while (pos + 4 <= extEnd)
    {
        uint16_t t = (data[pos] << 8) | data[pos + 1], sz = (data[pos + 2] << 8) | data[pos + 3];
        pos += 4;
        if (t == 0x0000)
        {
            if (pos + 2 > len)
                return false;
            uint16_t listLen = (data[pos] << 8) | data[pos + 1];
            pos += 2;
            uint32_t listEnd = pos + listLen;
            while (pos + 3 <= listEnd)
            {
                uint8_t nameType = data[pos++];
                uint16_t nameLen = (data[pos] << 8) | data[pos + 1];
                pos += 2;
                if (nameType == 0)
                {
                    if (pos + nameLen > len)
                        return false;
                    sni.assign((const char *)(data + pos), nameLen);
                    return true;
                }
                pos += nameLen;
            }
            return false;
        }
        pos += sz;
    }
    return false;
}

// ---- 재조립 함수 추가 ----
bool accumulateTlsRecord(const FlowId &flow,
                         const uint8_t *chunk,
                         size_t chunkLen,
                         std::string &outSni)
{
    auto &buf = tlsReassembly[flow];
    buf.insert(buf.end(), chunk, chunk + chunkLen);
    if (buf.size() < 5)
        return false;
    uint16_t recLen = (uint16_t(buf[3]) << 8) | buf[4];
    size_t fullLen = 5 + recLen;
    if (buf.size() < fullLen)
        return false;
    bool ok = parseTlsSni(buf.data(), fullLen, outSni);
    tlsReassembly.erase(flow);
    return ok;
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return -1;
    }
    const char *dev = argv[1];
    const std::string target = argv[2];
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp dst port 443", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    if (pcap_setfilter(handle, &fp) < 0)
    {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    pcap_freecode(&fp);

    if (getMyInfo(&MyInfo, dev) < 0)
    {
        fprintf(stderr, "failed to get interface info for %s\n", dev);
        pcap_close(handle);
        return -1;
    }

    int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rsock < 0)
    {
        perror("socket");
        pcap_close(handle);
        return -1;
    }
    int on = 1;
    if (setsockopt(rsock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
    {
        perror("setsockopt");
        close(rsock);
        pcap_close(handle);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
            break;

        PacketInfo *pi = (PacketInfo *)packet;
        if (pi->ethHdr_.type() != EthHdr::Ip4)
            continue;

        uint32_t ihl = pi->ipHdr_.hl() * 4;
        if (pi->ipHdr_.p() != IpHdr::Tcp)
            continue;
        uint32_t ipTotal = pi->ipHdr_.len();
        uint32_t thl = pi->tcpHdr_.off() * 4;
        uint32_t dataLen = ipTotal - ihl - thl;
        if (dataLen == 0)
            continue;

        const uint8_t *payload = packet + sizeof(EthHdr) + ihl + thl;
        // --- 재조립 적용 ---
        FlowId flow{pi->ipHdr_.sip(), pi->ipHdr_.dip(), pi->tcpHdr_.sport(), pi->tcpHdr_.dport()};
        std::string sni;
        if (!accumulateTlsRecord(flow, payload, dataLen, sni))
            continue;
        if (sni != target)
            continue;
        printf("Blocking SNI: %s\n", sni.c_str());

        // --- Forward RST/ACK ---
        PacketInfo *fpkt = (PacketInfo *)malloc(sizeof(PacketInfo));
        memcpy(fpkt, packet, sizeof(PacketInfo));
        fpkt->ethHdr_.smac_ = MyInfo.mac;
        fpkt->ipHdr_.len_ = htons(ihl + thl);
        fpkt->ipHdr_.sum_ = 0;
        fpkt->ipHdr_.sum_ = CheckSum((uint16_t *)&fpkt->ipHdr_, sizeof(IpHdr));

        uint32_t origSeq = pi->tcpHdr_.seq();
        uint32_t newSeq = origSeq + dataLen;
        fpkt->tcpHdr_.seq_ = htonl(newSeq);
        fpkt->tcpHdr_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        fpkt->tcpHdr_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        fpkt->tcpHdr_.sum_ = 0;

        ChecksumHdr phdr2;
        memset(&phdr2, 0, sizeof(phdr2));
        phdr2.srcAddr = (uint32_t)pi->ipHdr_.sip();
        phdr2.dstAddr = (uint32_t)pi->ipHdr_.dip();
        phdr2.proto = pi->ipHdr_.p();
        phdr2.tcpLen = htons(sizeof(TcpHdr));

        uint32_t csum2 = 0;
        csum2 += CheckSum((uint16_t *)&fpkt->tcpHdr_, sizeof(TcpHdr));
        csum2 += CheckSum((uint16_t *)&phdr2, sizeof(phdr2));
        csum2 = (csum2 & 0xFFFF) + (csum2 >> 16);
        fpkt->tcpHdr_.sum_ = (uint16_t)csum2;

        pcap_sendpacket(handle, (const u_char *)fpkt, sizeof(PacketInfo));
        free(fpkt);

        // --- Backward RST/ACK ---
        struct
        {
            IpHdr ip;
            TcpHdr tcp;
        } bpkt;

        memcpy(&bpkt.ip, &pi->ipHdr_, sizeof(IpHdr));
        bpkt.ip.sip_ = pi->ipHdr_.dip_;
        bpkt.ip.dip_ = pi->ipHdr_.sip_;
        bpkt.ip.len_ = htons(ihl + thl);
        bpkt.ip.ttl_ = 64;
        bpkt.ip.sum_ = 0;
        bpkt.ip.sum_ = CheckSum((uint16_t *)&bpkt.ip, sizeof(IpHdr));

        memcpy(&bpkt.tcp, &pi->tcpHdr_, sizeof(TcpHdr));
        bpkt.tcp.sport_ = pi->tcpHdr_.dport_;
        bpkt.tcp.dport_ = pi->tcpHdr_.sport_;
        bpkt.tcp.seq_ = pi->tcpHdr_.ack_;
        uint32_t newAck2 = origSeq + dataLen;
        bpkt.tcp.ack_ = htonl(newAck2);
        bpkt.tcp.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        bpkt.tcp.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        bpkt.tcp.sum_ = 0;

        ChecksumHdr phdr3;
        memset(&phdr3, 0, sizeof(phdr3));
        phdr3.srcAddr = (uint32_t)bpkt.ip.sip_;
        phdr3.dstAddr = (uint32_t)bpkt.ip.dip_;
        phdr3.proto = bpkt.ip.p();
        phdr3.tcpLen = htons(sizeof(TcpHdr));

        uint32_t csum3 = 0;
        csum3 += CheckSum((uint16_t *)&bpkt.tcp, sizeof(TcpHdr));
        csum3 += CheckSum((uint16_t *)&phdr3, sizeof(phdr3));
        csum3 = (csum3 & 0xFFFF) + (csum3 >> 16);
        bpkt.tcp.sum_ = (uint16_t)csum3;

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(std::string(pi->ipHdr_.sip()).c_str());

        sendto(rsock,
               &bpkt.ip,
               sizeof(IpHdr) + sizeof(TcpHdr),
               0,
               (struct sockaddr *)&sin,
               sizeof(sin));
    }

    close(rsock);
    pcap_close(handle);
    return 0;
}
