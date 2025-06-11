#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "ethhdr.h"
#include "iphdr.h"
#include "tcphdr.h"
#include "mac.h"

// 3바이트(24비트) 길이 필드 파싱
static uint32_t parse24(const uint8_t *b)
{
    return (uint32_t(b[0]) << 16) |
           (uint32_t(b[1]) << 8) |
           uint32_t(b[2]);
}

// Handshake 내부에서 SNI 확장 필드만 파싱하여 호스트명 추출
static std::string extractSni(const uint8_t *data, uint32_t len)
{
    if (len < 38)
        return "";
    size_t off = 2 + 32; // 버전(2) + 랜덤(32)
    if (off >= len)
        return "";
    uint8_t sidLen = data[off++];
    off += sidLen;
    if (off + 2 > len)
        return "";
    uint16_t csLen = ntohs(*reinterpret_cast<const uint16_t *>(data + off));
    off += 2 + csLen;
    if (off >= len)
        return "";
    uint8_t compLen = data[off++];
    off += compLen;
    if (off + 2 > len)
        return "";
    uint16_t extTot = ntohs(*reinterpret_cast<const uint16_t *>(data + off));
    off += 2;
    uint32_t endExt = off + extTot;
    while (off + 4 <= endExt && off + 4 <= len)
    {
        uint16_t t = ntohs(*reinterpret_cast<const uint16_t *>(data + off));
        uint16_t l = ntohs(*reinterpret_cast<const uint16_t *>(data + off + 2));
        off += 4;
        if (t == 0x0000 && l >= 5 && off + l <= len)
        {
            uint8_t nameType = data[off + 2];
            uint16_t nameLen = ntohs(*reinterpret_cast<const uint16_t *>(data + off + 3));
            if (nameType == 0 && off + 5 + nameLen <= len)
            {
                return std::string(reinterpret_cast<const char *>(data + off + 5), nameLen);
            }
        }
        off += l;
    }
    return "";
}

// Handshake 메시지 헤더 이후 섹션 파싱
static std::string parseHandshake(const uint8_t *p, uint32_t plen)
{
    if (plen < 4)
        return "";
    if (p[0] != 0x01)
        return ""; // ClientHello
    uint32_t hsLen = parse24(p + 1);
    if (plen < 4 + hsLen)
        return "";
    return extractSni(p + 4, hsLen);
}

// TCP 흐름 식별용 4-tuple
struct ConnKey
{
    Ip saddr;
    uint16_t sport;
    Ip daddr;
    uint16_t dport;
    bool operator<(ConnKey const &o) const
    {
        if (saddr != o.saddr)
            return saddr < o.saddr;
        if (sport != o.sport)
            return sport < o.sport;
        if (daddr != o.daddr)
            return daddr < o.daddr;
        return dport < o.dport;
    }
};

// 분할된 TLS 조각 상태 관리
struct TlsContext
{
    std::string buf;
    uint32_t expectRec;
    uint32_t expectHs;
    bool seenRec;
    bool seenHs;
    bool done;
    TlsContext() : expectRec(0), expectHs(0), seenRec(false), seenHs(false), done(false) {}
};

static std::map<ConnKey, TlsContext> ctxMap;

static bool isComplete(const TlsContext &c)
{
    return c.seenRec && c.seenHs && c.buf.size() == c.expectRec;
}

// 분할된 조각을 누적하여 SNI 추출 시점에 반환
static std::string processFragment(const ConnKey &key,
                                   const uint8_t *data,
                                   uint32_t len,
                                   bool isRec)
{
    auto &ctx = ctxMap[key];
    if (ctx.done)
        return "";

    // Record Header 파악
    if (isRec && !ctx.seenRec && len >= 5)
    {
        uint16_t recLen = ntohs(*reinterpret_cast<const uint16_t *>(data + 3));
        ctx.expectRec = 5 + recLen;
        ctx.seenRec = true;
    }
    ctx.buf.append(reinterpret_cast<const char *>(data), len);

    // Handshake Header 파악
    if (ctx.seenRec && !ctx.seenHs && ctx.buf.size() >= 9)
    {
        const uint8_t *hptr = reinterpret_cast<const uint8_t *>(ctx.buf.data()) + 5;
        if (hptr[0] == 0x01)
        {
            uint32_t hsLen = parse24(hptr + 1);
            ctx.expectHs = hsLen;
            ctx.seenHs = true;
            ctx.expectRec = 5 + 4 + hsLen;
        }
    }

    // 완전 수신 시 파싱 후 제거
    if (isComplete(ctx))
    {
        const uint8_t *hptr = reinterpret_cast<const uint8_t *>(ctx.buf.data()) + 5;
        uint32_t hlen = ctx.buf.size() - 5;
        std::string host = parseHandshake(hptr, hlen);
        ctx.done = true;
        ctxMap.erase(key);
        return host;
    }
    return "";
}

static void usage()
{
    std::cout << "syntax : tls-block <interface> <server_name>\n"
              << "sample : tls-block wlan0 naver.com\n";
}

// 서버 방향 RST+ACK 주입
static void injectServer(pcap_t *pc,
                         const uint8_t *orig,
                         const IpHdr *iph,
                         const TcpHdr *tcph,
                         uint16_t dlen,
                         const Mac &myMac)
{
    int ethL = sizeof(EthHdr);
    int ipL = iph->hl() * 4;
    int tcpL = tcph->off() * 4;
    int tot = ethL + ipL + tcpL;
    std::vector<uint8_t> out(tot);
    memcpy(out.data(), orig, tot);

    auto *eth = reinterpret_cast<EthHdr *>(out.data());
    eth->smac_ = myMac;

    auto *ip2 = reinterpret_cast<IpHdr *>(out.data() + ethL);
    ip2->len_ = htons(ipL + tcpL);
    ip2->sum_ = 0;
    ip2->sum_ = htons(IpHdr::calcChecksum(ip2));

    auto *tcp2 = reinterpret_cast<TcpHdr *>(out.data() + ethL + ipL);
    tcp2->seq_ = htonl(tcph->seq() + dlen);
    tcp2->flags_ = TcpHdr::Rst | TcpHdr::Ack;
    tcp2->sum_ = 0;
    tcp2->sum_ = htons(TcpHdr::calcChecksum(ip2, tcp2));

    if (pcap_sendpacket(pc, out.data(), tot) != 0)
    {
        std::cerr << "pcap_sendpacket error: " << pcap_geterr(pc) << '\n';
    }
}

// 클라이언트 방향 RST+ACK 주입
static void injectClient(const IpHdr *iph,
                         const TcpHdr *tcph,
                         uint16_t dlen)
{
    int ipL = iph->hl() * 4;
    int tcpL = tcph->off() * 4;
    int tot = ipL + tcpL;
    std::vector<uint8_t> out(tot);
    memset(out.data(), 0, tot);

    auto *ip2 = reinterpret_cast<IpHdr *>(out.data());
    ip2->v_hl_ = (4 << 4) | (ipL / 4);
    ip2->len_ = htons(tot);
    ip2->ttl_ = 128;
    ip2->p_ = IpHdr::Tcp;
    ip2->sip_ = htonl(iph->dip());
    ip2->dip_ = htonl(iph->sip());
    ip2->sum_ = 0;
    ip2->sum_ = htons(IpHdr::calcChecksum(ip2));

    auto *tcp2 = reinterpret_cast<TcpHdr *>(out.data() + ipL);
    tcp2->sport_ = htons(tcph->dport());
    tcp2->dport_ = htons(tcph->sport());
    tcp2->seq_ = htonl(tcph->ack());
    tcp2->ack_ = htonl(tcph->seq() + dlen);
    tcp2->off_rsvd_ = static_cast<uint8_t>((tcpL / 4) << 4);
    tcp2->flags_ = TcpHdr::Rst | TcpHdr::Ack;
    tcp2->win_ = htons(60000);
    tcp2->sum_ = 0;
    tcp2->sum_ = htons(TcpHdr::calcChecksum(ip2, tcp2));

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = tcp2->dport_;
    addr.sin_addr.s_addr = ip2->dip_;
    sendto(sd, out.data(), tot, 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    close(sd);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        usage();
        return 0;
    }
    std::string iface = argv[1];
    std::string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, -1, errbuf);
    if (!handle)
    {
        std::cerr << "pcap_open_live failed: " << errbuf << '\n';
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        perror("socket");
        return -1;
    }
    ifreq ifr{};
    strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(fd);
        return -1;
    }
    close(fd);
    Mac myMac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));

    std::cout << "Blocking \"" << pattern << "\" on " << iface << '\n';

    pcap_pkthdr *hdr;
    const uint8_t *pkt;
    int count = 0;
    while (true)
    {
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res != 1)
            break;

        auto *eth = reinterpret_cast<const EthHdr *>(pkt);
        if (eth->type() != EthHdr::Ip4)
            continue;
        auto *iph = reinterpret_cast<const IpHdr *>(pkt + sizeof(EthHdr));
        if (iph->p() != IpHdr::Tcp)
            continue;

        uint16_t ipL = iph->hl() * 4;
        auto *tcph = reinterpret_cast<const TcpHdr *>(pkt + sizeof(EthHdr) + ipL);
        uint16_t tcpL = tcph->off() * 4;
        uint16_t totL = iph->len();
        if (totL < ipL + tcpL)
            continue;
        uint16_t dlen = totL - ipL - tcpL;
        if (dlen == 0)
            continue;

        const uint8_t *data = pkt + sizeof(EthHdr) + ipL + tcpL;
        bool isRec = (dlen > 5 && data[0] == 0x16);

        ConnKey key{iph->sip(), tcph->sport(), iph->dip(), tcph->dport()};
        std::string host = processFragment(key, data, dlen, isRec);
        if (!host.empty() && host.find(pattern) != std::string::npos)
        {
            std::cout << " [" << ++count << "] " << host << '\n';
            injectServer(handle, pkt, iph, tcph, dlen, myMac);
            injectClient(iph, tcph, dlen);
        }
    }

    pcap_close(handle);
    return 0;
}
