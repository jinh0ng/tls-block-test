#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
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
    std::printf("syntax : tls-block <interface> <server name>\n");
    std::printf("sample : tls-block wlan0 naver.com\n");
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

// 세그먼트 재조립용 키
struct FlowId
{
    Ip src;
    Ip dst;
    uint16_t sport;
    uint16_t dport;
    bool operator==(FlowId const &o) const noexcept
    {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport;
    }
};

namespace std
{
    template <>
    struct hash<FlowId>
    {
        size_t operator()(FlowId const &f) const noexcept
        {
            uint64_t a = (uint64_t)f.src << 32 | uint32_t(f.dst);
            uint64_t b = (uint64_t)f.sport << 16 | f.dport;
            return hash<uint64_t>()(a) ^ hash<uint64_t>()(b);
        }
    };
}

static std::unordered_map<FlowId, std::vector<uint8_t>> tlsBuffer;

// SNI 파싱 함수: TLS ClientHello 내 SNI 확장 추출
static bool parseTlsSni(const uint8_t *data, uint32_t len, std::string &sni)
{
    if (len < 5)
        return false;
    uint32_t pos = 0;

    // TLS 레코드 레이어
    uint8_t recordType = data[pos++];
    if (recordType != 22)
        return false; // Handshake
    pos += 2;         // Version
    uint16_t recordLen = (uint16_t(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (recordLen + 5 > len)
        return false;

    // Handshake 메시지
    uint8_t hsType = data[pos++];
    if (hsType != 1)
        return false; // ClientHello
    uint32_t hsLen = (uint32_t(data[pos]) << 16) | (uint32_t(data[pos + 1]) << 8) | data[pos + 2];
    pos += 3;
    if (hsLen + 4 > recordLen)
        return false;

    // Skip version(2) + random(32)
    pos += 2 + 32;
    if (pos + 1 > len)
        return false;

    // SessionID
    uint8_t sidLen = data[pos++];
    pos += sidLen;
    if (pos + 2 > len)
        return false;

    // CipherSuites
    uint16_t csLen = (uint16_t(data[pos]) << 8) | data[pos + 1];
    pos += 2 + csLen;
    if (pos + 1 > len)
        return false;

    // CompressionMethods
    uint8_t compLen = data[pos++];
    pos += compLen;
    if (pos + 2 > len)
        return false;

    // Extensions
    uint16_t extTotal = (uint16_t(data[pos]) << 8) | data[pos + 1];
    pos += 2;
    uint32_t extEnd = pos + extTotal;
    while (pos + 4 <= extEnd)
    {
        uint16_t extType = (uint16_t(data[pos]) << 8) | data[pos + 1];
        uint16_t extLen = (uint16_t(data[pos + 2]) << 8) | data[pos + 3];
        pos += 4;
        if (extType == 0x0000)
        { // SNI
            if (pos + 2 > len)
                return false;
            uint16_t listLen = (uint16_t(data[pos]) << 8) | data[pos + 1];
            pos += 2;
            uint32_t listEnd = pos + listLen;
            while (pos + 3 <= listEnd)
            {
                uint8_t nameType = data[pos++];
                uint16_t nameLen = (uint16_t(data[pos]) << 8) | data[pos + 1];
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
        pos += extLen;
    }
    return false;
}

// ---------------------------
bool parseTlsSni(const uint8_t *data, uint32_t len, std::string &sni);

// 패킷 조각을 모아 완전한 TLS 레코드 시 SNI 문자열 반환
static std::string process_fragment(const FlowId &flow,
                                    const uint8_t *chunk,
                                    size_t chunkLen,
                                    bool isTls)
{
    if (!isTls)
        return std::string();
    auto &buf = tlsBuffer[flow];
    buf.insert(buf.end(), chunk, chunk + chunkLen);
    if (buf.size() < 5)
        return std::string();
    uint16_t recLen = (uint16_t(buf[3]) << 8) | buf[4];
    size_t full = 5 + recLen;
    if (buf.size() < full)
        return std::string();
    std::string sni;
    if (parseTlsSni(buf.data(), full, sni))
        tlsBuffer.erase(flow);
    else if (buf.size() > 65536)
        tlsBuffer.erase(flow);
    return sni;
}

int getMyInfo(t_info *info, const char *dev)
{
    struct ifreq ifr;
    int fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        close(fd);
        return -1;
    }
    info->mac = Mac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0)
    {
        close(fd);
        return -1;
    }
    uint32_t raw = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr);
    info->ip = Ip(raw);
    std::printf("My MAC: %s\n", std::string(info->mac).c_str());
    std::printf("My IP: %s\n", std::string(info->ip).c_str());
    close(fd);
    return 0;
}

uint16_t CheckSum(uint16_t *buf, int sz)
{
    uint32_t sum = 0;
    while (sz > 1)
    {
        sum += *buf++;
        sz -= 2;
    }
    if (sz)
        sum += *(uint8_t *)buf;
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
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
        std::fprintf(stderr, "%s\n", errbuf);
        return -1;
    }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "tcp dst port 443", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);
    pcap_freecode(&fp);

    if (getMyInfo(&MyInfo, dev) < 0)
    {
        std::fprintf(stderr, "getMyInfo failed\n");
        return -1;
    }

    int rsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(rsock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    while (true)
    {
        struct pcap_pkthdr *hdr;
        const u_char *pkt;
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res <= 0)
            continue;

        PacketInfo *pi = (PacketInfo *)pkt;
        if (pi->ethHdr_.type() != EthHdr::Ip4)
            continue;
        uint32_t ihl = pi->ipHdr_.hl() * 4;
        if (pi->ipHdr_.p() != IpHdr::Tcp)
            continue;
        uint32_t total = pi->ipHdr_.len();
        uint32_t thl = pi->tcpHdr_.off() * 4;
        uint32_t dataLen = total - ihl - thl;
        if (dataLen == 0)
            continue;

        const uint8_t *payload = pkt + sizeof(EthHdr) + ihl + thl;
        bool isTls = (dataLen > 5 && payload[0] == 0x16);
        FlowId flow{pi->ipHdr_.sip(), pi->ipHdr_.dip(), pi->tcpHdr_.sport(), pi->tcpHdr_.dport()};
        std::string host = process_fragment(flow, payload, dataLen, isTls);
        if (host.empty() || host != target)
            continue;

        std::printf("Blocking SNI: %s\n", host.c_str());

        // Forward RST
        PacketInfo *fpkt = (PacketInfo *)std::malloc(sizeof(PacketInfo));
        std::memcpy(fpkt, pkt, sizeof(PacketInfo));
        fpkt->ethHdr_.smac_ = MyInfo.mac;
        fpkt->ipHdr_.len_ = htons(ihl + thl);
        fpkt->ipHdr_.sum_ = 0;
        fpkt->ipHdr_.sum_ = CheckSum((uint16_t *)&fpkt->ipHdr_, sizeof(IpHdr));
        uint32_t seq0 = pi->tcpHdr_.seq();
        fpkt->tcpHdr_.seq_ = htonl(seq0 + dataLen);
        fpkt->tcpHdr_.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        fpkt->tcpHdr_.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        fpkt->tcpHdr_.sum_ = 0;
        ChecksumHdr ph;
        std::memset(&ph, 0, sizeof(ph));
        ph.srcAddr = (uint32_t)pi->ipHdr_.sip();
        ph.dstAddr = (uint32_t)pi->ipHdr_.dip();
        ph.proto = pi->ipHdr_.p();
        ph.tcpLen = htons(sizeof(TcpHdr));
        uint32_t csum = 0;
        csum += CheckSum((uint16_t *)&fpkt->tcpHdr_, sizeof(TcpHdr));
        csum += CheckSum((uint16_t *)&ph, sizeof(ph));
        csum = (csum & 0xFFFF) + (csum >> 16);
        fpkt->tcpHdr_.sum_ = (uint16_t)csum;
        pcap_sendpacket(handle, (const u_char *)fpkt, sizeof(PacketInfo));
        std::free(fpkt);

        // Backward RST
        struct
        {
            IpHdr ip;
            TcpHdr tcp;
        } bp;
        std::memcpy(&bp.ip, &pi->ipHdr_, sizeof(IpHdr));
        bp.ip.sip_ = pi->ipHdr_.dip_;
        bp.ip.dip_ = pi->ipHdr_.sip_;
        bp.ip.len_ = htons(ihl + thl);
        bp.ip.ttl_ = 64;
        bp.ip.sum_ = 0;
        bp.ip.sum_ = CheckSum((uint16_t *)&bp.ip, sizeof(IpHdr));
        std::memcpy(&bp.tcp, &pi->tcpHdr_, sizeof(TcpHdr));
        bp.tcp.sport_ = pi->tcpHdr_.dport_;
        bp.tcp.dport_ = pi->tcpHdr_.sport_;
        bp.tcp.seq_ = pi->tcpHdr_.ack_;
        bp.tcp.ack_ = htonl(seq0 + dataLen);
        bp.tcp.flags_ = TcpHdr::Rst | TcpHdr::Ack;
        bp.tcp.off_rsvd_ = (sizeof(TcpHdr) / 4) << 4;
        bp.tcp.sum_ = 0;
        ChecksumHdr ph2;
        std::memset(&ph2, 0, sizeof(ph2));
        ph2.srcAddr = (uint32_t)bp.ip.sip_;
        ph2.dstAddr = (uint32_t)bp.ip.dip_;
        ph2.proto = bp.ip.p();
        ph2.tcpLen = htons(sizeof(TcpHdr));
        uint32_t c2 = 0;
        c2 += CheckSum((uint16_t *)&bp.tcp, sizeof(TcpHdr));
        c2 += CheckSum((uint16_t *)&ph2, sizeof(ph2));
        c2 = (c2 & 0xFFFF) + (c2 >> 16);
        bp.tcp.sum_ = (uint16_t)c2;
        struct sockaddr_in sin;
        std::memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = inet_addr(std::string(pi->ipHdr_.sip()).c_str());
        sendto(rsock, &bp.ip, sizeof(IpHdr) + sizeof(TcpHdr), 0,
               (struct sockaddr *)&sin, sizeof(sin));
    }

    close(rsock);
    pcap_close(handle);
    return 0;
}
