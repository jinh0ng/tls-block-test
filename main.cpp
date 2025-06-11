// main.cpp
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

// 세션 키: srcIP, srcPort, dstIP, dstPort
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

// 분할된 TLS 조각을 저장할 맵
static std::map<ConnKey, std::vector<uint8_t>> reassembly_map;

// 16비트 빅엔디언 파싱
static uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

// ClientHello 메시지에서 SNI 확장만 찾아 반환
static std::string parseSniFromClientHello(const uint8_t *data, size_t len)
{
    // TLS Record (5바이트) 검사
    if (len < 5 || data[0] != 0x16)
        return {};
    size_t rec_len = read_u16(data + 3);
    if (5 + rec_len > len)
        return {};
    const uint8_t *ptr = data + 5;
    size_t remain = rec_len;
    // Handshake(1) | Len(3)
    if (remain < 4 || ptr[0] != 0x01)
        return {};
    size_t hs_len = (size_t(ptr[1]) << 16) | (size_t(ptr[2]) << 8) | ptr[3];
    ptr += 4;
    remain -= 4;
    if (hs_len + 4 > rec_len || remain < hs_len)
        return {};

    // ClientHello 구조: 버전(2)+랜덤(32)+세션IDLen(1)+SessionID+CipherSuiteLen(2)+CipherSuites+
    // CompressionLen(1)+Compressions+ExtensionsLen(2)+Extensions
    // 대략적인 offset 계산
    const uint8_t *end = ptr + hs_len;
    // skip version+random
    ptr += 2 + 32;
    if (ptr + 1 > end)
        return {};
    // SessionID
    uint8_t sidlen = *ptr++;
    ptr += sidlen;
    if (ptr + 2 > end)
        return {};
    // CipherSuites
    uint16_t cslen = read_u16(ptr);
    ptr += 2 + cslen;
    if (ptr + 1 > end)
        return {};
    // Compression
    uint8_t comlen = *ptr++;
    ptr += comlen;
    if (ptr + 2 > end)
        return {};
    // Extensions
    uint16_t ext_total = read_u16(ptr);
    ptr += 2;
    const uint8_t *ext_end = ptr + ext_total;
    while (ptr + 4 <= ext_end)
    {
        uint16_t ext_type = read_u16(ptr);
        uint16_t ext_len = read_u16(ptr + 2);
        ptr += 4;
        if (ptr + ext_len > ext_end)
            break;
        if (ext_type == 0x0000)
        { // SNI extension
            // ServerNameListLen(2)
            uint16_t list_len = read_u16(ptr);
            ptr += 2;
            const uint8_t *lst_end = ptr + list_len;
            while (ptr + 3 <= lst_end)
            {
                uint8_t name_type = *ptr++;
                uint16_t namelen = read_u16(ptr);
                ptr += 2;
                if (ptr + namelen > lst_end)
                    break;
                // 첫 번째 호스트 이름만 반환
                return std::string(reinterpret_cast<const char *>(ptr), namelen);
            }
        }
        ptr += ext_len;
    }
    return {};
}

// 조각 재조립 후 SNI 파싱
static std::string processTlsFragment(ConnKey const &key,
                                      const uint8_t *data,
                                      size_t len,
                                      bool isTls)
{
    if (!isTls)
        return {};
    auto &buf = reassembly_map[key];
    // 새 조각 합치기
    buf.insert(buf.end(), data, data + len);
    // 전체 레코드 길이 확인
    if (buf.size() < 5)
        return {};
    uint16_t rec_len = read_u16(buf.data() + 3);
    if (buf.size() < 5 + rec_len)
        return {};
    // 충분히 모였으면 SNI 파싱
    std::string host = parseSniFromClientHello(buf.data(), buf.size());
    // 사용했으면 버퍼 비우기
    buf.clear();
    return host;
}

static void sendRSTToServer(pcap_t *handle,
                            const uint8_t *orig,
                            const IpHdr *iph,
                            const TcpHdr *tcph,
                            uint16_t payloadLen,
                            const Mac &myMac)
{
    int ethL = sizeof(EthHdr);
    int ipL = iph->hl() * 4;
    int tcpL = tcph->off() * 4;
    int tot = ethL + ipL + tcpL;
    std::vector<uint8_t> pkt(tot);
    std::memcpy(pkt.data(), orig, tot);

    auto *eth = reinterpret_cast<EthHdr *>(pkt.data());
    eth->smac_ = myMac;

    auto *ip2 = reinterpret_cast<IpHdr *>(pkt.data() + ethL);
    ip2->len_ = htons(ipL + tcpL);
    ip2->sum_ = 0;
    ip2->sum_ = htons(IpHdr::calcChecksum(ip2));

    auto *tcp2 = reinterpret_cast<TcpHdr *>(pkt.data() + ethL + ipL);
    tcp2->seq_ = htonl(tcph->seq() + payloadLen);
    tcp2->flags_ = TcpHdr::Rst | TcpHdr::Ack;
    tcp2->sum_ = 0;
    tcp2->sum_ = htons(TcpHdr::calcChecksum(ip2, tcp2));

    if (pcap_sendpacket(handle, pkt.data(), tot) != 0)
    {
        std::cerr << "pcap_sendpacket error: "
                  << pcap_geterr(handle) << "\n";
    }
}

static void sendRSTToClient(const IpHdr *iph,
                            const TcpHdr *tcph,
                            uint16_t payloadLen)
{
    int ipL = iph->hl() * 4;
    int tcpL = tcph->off() * 4;
    int tot = ipL + tcpL;
    std::vector<uint8_t> pkt(tot);
    std::memset(pkt.data(), 0, tot);

    auto *ip2 = reinterpret_cast<IpHdr *>(pkt.data());
    ip2->v_hl_ = (4 << 4) | (ipL / 4);
    ip2->len_ = htons(tot);
    ip2->ttl_ = 128;
    ip2->p_ = IpHdr::Tcp;
    ip2->sip_ = htonl(iph->dip());
    ip2->dip_ = htonl(iph->sip());
    ip2->sum_ = 0;
    ip2->sum_ = htons(IpHdr::calcChecksum(ip2));

    auto *tcp2 = reinterpret_cast<TcpHdr *>(pkt.data() + ipL);
    tcp2->sport_ = htons(tcph->dport());
    tcp2->dport_ = htons(tcph->sport());
    tcp2->seq_ = htonl(tcph->ack());
    tcp2->ack_ = htonl(tcph->seq() + payloadLen);
    tcp2->off_rsvd_ = uint8_t((tcpL / 4) << 4);
    tcp2->flags_ = TcpHdr::Rst | TcpHdr::Ack;
    tcp2->win_ = htons(60000);
    tcp2->sum_ = 0;
    tcp2->sum_ = htons(TcpHdr::calcChecksum(ip2, tcp2));

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int on = 1;
    setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = tcp2->dport_;
    dst.sin_addr.s_addr = ip2->dip_;
    sendto(sd, pkt.data(), tot, 0,
           reinterpret_cast<sockaddr *>(&dst),
           sizeof(dst));
    close(sd);
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        std::cout << "syntax : tls-block <interface> <server_name>\n"
                  << "sample : tls-block wlan0 naver.com\n";
        return 0;
    }
    std::string iface = argv[1];
    std::string pattern = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface.c_str(), BUFSIZ, 1, -1, errbuf);
    if (!handle)
    {
        std::cerr << "pcap_open_live failed: " << errbuf << "\n";
        return -1;
    }

    // 내 MAC 얻기
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    Mac myMac(reinterpret_cast<uint8_t *>(ifr.ifr_hwaddr.sa_data));

    std::cout << "Blocking \"" << pattern
              << "\" on " << iface << "\n";

    pcap_pkthdr *hdr;
    const uint8_t *pkt;
    int count = 0;
    while (true)
    {
        int res = pcap_next_ex(handle, &hdr, &pkt);
        if (res != 1)
            break;

        // Eth → IPv4 → TCP 필터
        auto *eth = reinterpret_cast<const EthHdr *>(pkt);
        if (eth->type() != EthHdr::Ip4)
            continue;
        auto *iph = reinterpret_cast<const IpHdr *>(pkt + sizeof(EthHdr));
        if (iph->p() != IpHdr::Tcp)
            continue;

        uint16_t ipL = iph->hl() * 4;
        auto *tcph = reinterpret_cast<const TcpHdr *>(
            pkt + sizeof(EthHdr) + ipL);
        uint16_t tcpL = tcph->off() * 4;
        uint16_t totL = iph->len();
        uint16_t appL = totL - ipL - tcpL;
        if (appL == 0)
            continue;

        const uint8_t *payload = pkt + sizeof(EthHdr) + ipL + tcpL;
        bool isTls = (appL > 5 && payload[0] == 0x16);

        ConnKey key{iph->sip(), tcph->sport(),
                    iph->dip(), tcph->dport()};
        std::string host =
            processTlsFragment(key, payload, appL, isTls);

        if (!host.empty() && host.find(pattern) != std::string::npos)
        {
            std::cout << " [" << ++count
                      << "] " << host << "\n";
            sendRSTToServer(handle, pkt, iph, tcph, appL, myMac);
            sendRSTToClient(iph, tcph, appL);
        }
    }

    pcap_close(handle);
    return 0;
}
