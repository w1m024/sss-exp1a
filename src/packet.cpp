#include "packet.hpp"
#include "dns.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <limits>
#include <utility>
#include <iomanip>
#include <sstream>

namespace wirelens {
namespace {
struct Decoder {
    Packet p;
    std::size_t end;
    uint16_t u16(std::size_t o) const { return (uint16_t(p.bytes[o]) << 8) | p.bytes[o + 1]; }
    uint32_t u32(std::size_t o) const { return (uint32_t(u16(o)) << 16) | u16(o + 2); }
    bool need(std::size_t o, std::size_t n) {
        if (o > end || n > end - o) { p.malformed = true; return false; }
        if (o > p.bytes.size() || n > p.bytes.size() - o) { p.truncated = true; return false; }
        return true;
    }
    void field(const char* s, const char* n, std::string v, std::size_t o, std::size_t l) {
        p.fields.push_back({s, n, std::move(v), o, l});
    }
    void number(const char* s, const char* n, uint64_t v, std::size_t o, std::size_t l) {
        field(s, n, std::to_string(v), o, l);
    }
    void mac(const char* name, std::size_t offset) {
        std::ostringstream text;
        for (std::size_t i = 0; i < 6; ++i) {
            if (i) text << ':';
            text << std::hex << std::setw(2) << std::setfill('0') << unsigned(p.bytes[offset + i]);
        }
        field("Ethernet", name, text.str(), offset, 6);
    }
    void address(const char* section, std::size_t o, int family, bool source) {
        char text[INET6_ADDRSTRLEN] = {};
        inet_ntop(family, p.bytes.data() + o, text, sizeof(text));
        (source ? p.source : p.destination) = text;
        field(section, source ? "source" : "destination", text, o, family == AF_INET ? 4 : 16);
    }
    void http(std::size_t o) {
        const auto visible = std::min(end, p.bytes.size());
        if (o >= visible) return;
        std::string line;
        for (auto i = o; i < visible; ++i) {
            const auto c = p.bytes[i];
            if (c == '\r') {
                if (i + 1 >= visible || p.bytes[i + 1] != '\n') return;
                auto version = [](const std::string& s) { return s == "HTTP/1.0" || s == "HTTP/1.1"; };
                bool valid = false;
                if (line.size() >= 13 && version(line.substr(0, 8)) && line[8] == ' ' &&
                    line[9] >= '1' && line[9] <= '5' && line[10] >= '0' && line[10] <= '9' &&
                    line[11] >= '0' && line[11] <= '9' && line[12] == ' ') valid = true;
                const auto a = line.find(' '), b = line.rfind(' ');
                if (a != std::string::npos && b > a + 1 && version(line.substr(b + 1))) {
                    const std::string separators = "()<>@,;:\\\"/[]?={} \t";
                    valid = a > 0 && std::all_of(line.begin(), line.begin() + a, [&](unsigned char c) {
                        return c > 32 && c < 127 && separators.find(char(c)) == std::string::npos;
                    }) && line.substr(a + 1, b - a - 1).find(' ') == std::string::npos;
                }
                if (valid) { p.protocol = "HTTP"; p.http_line = line; field("HTTP", "first_line", line, o, i + 2 - o); }
                return;
            }
            if (c < 32 || c > 126) return;
            line += char(c);
        }
    }
    void transport(std::size_t o, uint8_t proto) {
        if (proto == 6) p.transport = "TCP";
        else if (proto == 17) p.transport = "UDP";
        else if (proto == 1 && p.network == "IPv4") p.transport = "ICMP";
        else if (proto == 58 && p.network == "IPv6") p.transport = "ICMPv6";
        else return;
        p.protocol = p.transport;
        if (p.fragmented) return;
        if (proto == 6 || proto == 17) {
            const std::size_t minimum = proto == 6 ? 20 : 8;
            if (!need(o, minimum)) return;
            std::size_t header = minimum;
            if (proto == 6) {
                header = (p.bytes[o + 12] >> 4) * 4;
                if (header < 20) { p.malformed = true; return; }
                if (!need(o, header)) return;
            } else {
                auto length = u16(o + 4);
                number("UDP", "length", length, o + 4, 2);
                number("UDP", "checksum", u16(o + 6), o + 6, 2);
                if (length < 8 || length > end - o) { p.malformed = true; return; }
                end = o + length;
                if (end > p.bytes.size()) p.truncated = true;
            }
            p.source_port = u16(o); p.destination_port = u16(o + 2);
            number(p.transport.c_str(), "source_port", p.source_port, o, 2);
            number(p.transport.c_str(), "destination_port", p.destination_port, o + 2, 2);
            if (proto == 6) {
                p.tcp_sequence = u32(o + 4); p.tcp_ack = u32(o + 8); p.tcp_flag_bits = p.bytes[o + 13];
                number("TCP", "sequence", p.tcp_sequence, o + 4, 4);
                number("TCP", "acknowledgment", p.tcp_ack, o + 8, 4);
                number("TCP", "header_length", header, o + 12, 1);
                number("TCP", "window", u16(o + 14), o + 14, 2);
                number("TCP", "checksum", u16(o + 16), o + 16, 2);
                const char* names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
                for (unsigned i = 0; i < 8; ++i) if (p.tcp_flag_bits & (1u << i)) {
                    if (!p.tcp_flags.empty()) p.tcp_flags += " ";
                    p.tcp_flags += names[i];
                }
                field("TCP", "flags", p.tcp_flags, o + 13, 1);
                http(o + header);
                if ((p.source_port == 53 || p.destination_port == 53) && end <= p.bytes.size() && end >= o + header + 2) {
                    auto start = o + header;
                    const auto length = u16(start);
                    if (length == end - start - 2) decode_dns(p, start + 2, length);
                }
            } else if ((p.source_port == 53 || p.destination_port == 53 || p.source_port == 5353 || p.destination_port == 5353) && end <= p.bytes.size()) {
                decode_dns(p, o + header, end - o - header);
            }
        } else if (need(o, 8)) {
            number(p.transport.c_str(), "type", p.bytes[o], o, 1);
            number(p.transport.c_str(), "code", p.bytes[o + 1], o + 1, 1);
        }
    }
    void ip(std::size_t o, uint16_t type) {
        if (type != 0x0800 && type != 0x86dd) return;
        const bool v6 = type == 0x86dd;
        p.network = p.protocol = v6 ? "IPv6" : "IPv4";
        if (!need(o, v6 ? 40 : 20)) return;
        if ((p.bytes[o] >> 4) != (v6 ? 6 : 4)) { p.malformed = true; return; }
        if (v6) {
            end = o + 40 + u16(o + 4);
            if (end > p.bytes.size()) p.truncated = true;
            number("IPv6", "payload_length", u16(o + 4), o + 4, 2);
            number("IPv6", "next_header", p.bytes[o + 6], o + 6, 1);
            number("IPv6", "hop_limit", p.bytes[o + 7], o + 7, 1);
            number("IPv6", "flow_label", u32(o) & 0xfffff, o, 4);
            address("IPv6", o + 8, AF_INET6, true); address("IPv6", o + 24, AF_INET6, false);
            const auto next = p.bytes[o + 6];
            if (next == 44) {
                p.fragmented = true;
                if (need(o + 40, 8)) number("IPv6", "fragment_offset_flags", u16(o + 42), o + 42, 2);
                return;
            }
            // Extension headers (including jumbo payloads) are intentionally not traversed.
            if (next == 0 || next == 43 || next == 60 || next == 51 || next == 50 || next == 135) {
                field("IPv6", "extension_status", "not parsed", o + 6, 1);
                return;
            }
            transport(o + 40, next);
        } else {
            const std::size_t header = (p.bytes[o] & 15) * 4, total = u16(o + 2);
            number("IPv4", "header_length", header, o, 1);
            number("IPv4", "total_length", total, o + 2, 2);
            if (header < 20 || total < header) { p.malformed = true; return; }
            end = o + total;
            if (end > p.bytes.size()) p.truncated = true;
            if (!need(o, header)) return;
            address("IPv4", o + 12, AF_INET, true); address("IPv4", o + 16, AF_INET, false);
            p.fragmented = (u16(o + 6) & 0x3fff) != 0;
            number("IPv4", "fragment_offset_flags", u16(o + 6), o + 6, 2);
            number("IPv4", "protocol", p.bytes[o + 9], o + 9, 1);
            number("IPv4", "identification", u16(o + 4), o + 4, 2);
            number("IPv4", "ttl", p.bytes[o + 8], o + 8, 1);
            number("IPv4", "checksum", u16(o + 10), o + 10, 2);
            transport(o + header, p.bytes[o + 9]);
        }
    }
    void decode() {
        std::size_t o = 0; uint16_t type = 0;
        switch (p.datalink) {
        case 1:
            if (!need(0, 14)) return;
            type = u16(12); o = 14;
            mac("destination_mac", 0); mac("source_mac", 6);
            number("Ethernet", "type", type, 12, 2);
            for (int tags = 0; type == 0x8100 || type == 0x88a8 || type == 0x9100; ++tags) {
                if (tags == 2) { p.malformed = true; return; }
                if (!need(o, 4)) return;
                number("VLAN", "tci", u16(o), o, 2); type = u16(o + 2); o += 4;
            }
            break;
        case 113:
            if (!need(0, 16)) return;
            type = u16(14); o = 16; number("SLL", "protocol", type, 14, 2); break;
        case 276:
            if (!need(0, 20)) return;
            type = u16(0); o = 20; number("SLL2", "protocol", type, 0, 2); break;
        case 0: {
            if (!need(0, 4)) return;
            const uint32_t le = uint32_t(p.bytes[0]) | (uint32_t(p.bytes[1]) << 8) |
                                (uint32_t(p.bytes[2]) << 16) | (uint32_t(p.bytes[3]) << 24);
            auto family = le;
            if (family != 2 && family != 10 && family != 24 && family != 28 && family != 30) family = u32(0);
            if (family == 2) type = 0x0800;
            else if (family == 10 || family == 24 || family == 28 || family == 30) type = 0x86dd;
            o = 4; number("NULL", "family", family, 0, 4); break;
        }
        case 12:
            if (!need(0, 1)) return;
            if ((p.bytes[0] >> 4) == 4) type = 0x0800;
            else if ((p.bytes[0] >> 4) == 6) type = 0x86dd;
            else p.malformed = true;
            break;
        default: return;
        }
        ip(o, type);
    }
};
}
Packet decode_packet(std::vector<uint8_t> bytes, int datalink, int64_t timestamp_us, uint32_t wire_length) {
    Decoder d;
    d.p.bytes = std::move(bytes); d.p.datalink = datalink;
    d.p.timestamp_us = timestamp_us; d.p.wire_length = wire_length;
    // wire_length is metadata; protocol bounds come exclusively from protocol headers.
    d.end = std::numeric_limits<std::size_t>::max();
    d.p.truncated = wire_length > d.p.bytes.size();
    d.decode();
    if (d.p.summary.empty()) d.p.summary = d.p.http_line.empty() ? d.p.protocol : d.p.http_line;
    if (!d.p.source.empty()) d.p.summary += " " + d.p.source + " -> " + d.p.destination;
    if (d.p.fragmented) d.p.summary += " [fragmented]";
    if (d.p.malformed) d.p.summary += " [malformed]";
    if (d.p.truncated) d.p.summary += " [truncated]";
    return std::move(d.p);
}
}
