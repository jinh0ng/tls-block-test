#pragma once

#include "iphdr.h"

#pragma pack(push, 1)
struct TcpHdr final
{
    uint16_t sport_;
    uint16_t dport_;
    uint32_t seq_;
    uint32_t ack_;
    uint8_t off_rsvd_;
    uint8_t flags_;
    uint16_t win_;
    uint16_t sum_;
    uint16_t urp_;

    uint16_t sport() const { return ntohs(sport_); }
    uint16_t dport() const { return ntohs(dport_); }
    uint32_t seq() const { return ntohl(seq_); }
    uint32_t ack() const { return ntohl(ack_); }
    uint8_t off() const { return (off_rsvd_ & 0xF0) >> 4; }
    uint8_t rsvd() const { return off_rsvd_ & 0x0F; }
    uint8_t flags() const { return flags_; }
    uint16_t win() const { return ntohs(win_); }
    uint16_t sum() const { return ntohs(sum_); }
    uint16_t urp() const { return ntohs(urp_); }

    // flag_
    enum : uint8_t
    {
        Urg = 0x20,
        Ack = 0x10,
        Psh = 0x08,
        Rst = 0x04,
        Syn = 0x02,
        Fin = 0x01
    };

    static uint16_t calcChecksum(IpHdr *ipHdr, TcpHdr *tcpHdr);
};
// typedef TcpHdr *PTcpHdr;
#pragma pack(pop)
