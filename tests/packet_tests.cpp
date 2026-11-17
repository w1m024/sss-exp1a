#include "packet.hpp"
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

// Always active, including builds with NDEBUG.
#define CHECK(x) do { if (!(x)) { std::cerr << __FILE__ << ':' << __LINE__ << ": " #x "\n"; std::abort(); } } while (false)
using Bytes = std::vector<uint8_t>;
using wirelens::Packet;
void put16(Bytes& b, std::size_t o, unsigned v) { b[o] = uint8_t(v >> 8); b[o + 1] = uint8_t(v); }
Bytes tcp(const std::string& data = "", unsigned port = 8080) {
    Bytes b(20); put16(b, 0, 12345); put16(b, 2, port);
    b[4] = 0x12; b[7] = 0x34; b[8] = 0xab; b[11] = 0xcd;
    b[12] = 0x50; b[13] = 0x12; b.insert(b.end(), data.begin(), data.end()); return b;
}
Bytes v4(const Bytes& payload, unsigned protocol = 6, unsigned header = 20) {
    Bytes b(header); b[0] = uint8_t(0x40 | (header / 4)); put16(b, 2, unsigned(header + payload.size()));
    b[8] = 64; b[9] = uint8_t(protocol); b[12] = 192; b[13] = 0; b[14] = 2; b[15] = 1;
    b[16] = 198; b[17] = 51; b[18] = 100; b[19] = 2;
    b.insert(b.end(), payload.begin(), payload.end()); return b;
}
Bytes v6(const Bytes& payload, unsigned protocol = 6) {
    Bytes b(40); b[0] = 0x60; put16(b, 4, unsigned(payload.size())); b[6] = uint8_t(protocol); b[7] = 64;
    b[8] = 0x20; b[9] = 1; b[10] = 0x0d; b[11] = 0xb8; b[23] = 1;
    b[24] = 0x20; b[25] = 1; b[26] = 0x0d; b[27] = 0xb8; b[39] = 2;
    b.insert(b.end(), payload.begin(), payload.end()); return b;
}
Bytes link(const Bytes& ip, int dlt, unsigned tags = 0, bool big = false) {
    const unsigned type = (ip[0] >> 4) == 6 ? 0x86dd : 0x0800;
    Bytes b;
    if (dlt == 1) {
        b.resize(14 + tags * 4); put16(b, 12, tags ? 0x88a8 : type);
        for (unsigned i = 0; i < tags; ++i) { put16(b, 14 + i * 4, i + 1); put16(b, 16 + i * 4, i + 1 == tags ? type : 0x8100); }
    } else if (dlt == 113) { b.resize(16); put16(b, 14, type); }
    else if (dlt == 276) { b.resize(20); put16(b, 0, type); }
    else if (dlt == 0) { b.resize(4); b[big ? 3 : 0] = type == 0x0800 ? 2 : 30; }
    b.insert(b.end(), ip.begin(), ip.end()); return b;
}
Packet parse(const Bytes& b, int dlt = 12, unsigned wire = 0) {
    auto p = wirelens::decode_packet(b, dlt, 123456, wire ? wire : unsigned(b.size()));
    CHECK(p.bytes == b); CHECK(p.datalink == dlt); CHECK(p.timestamp_us == 123456);
    CHECK(p.wire_length == (wire ? wire : b.size())); CHECK(p.flow_id.empty());
    for (const auto& f : p.fields) { CHECK(!f.section.empty()); CHECK(!f.name.empty()); CHECK(f.offset <= b.size()); CHECK(f.length <= b.size() - f.offset); }
    CHECK(!p.summary.empty()); return p;
}
void links_and_fields() {
    for (int dlt : {1, 113, 276, 0, 12}) {
        auto p = parse(link(v4(tcp()), dlt), dlt);
        CHECK(p.network == "IPv4"); CHECK(p.transport == "TCP"); CHECK(p.protocol == "TCP");
        CHECK(p.source == "192.0.2.1"); CHECK(p.destination == "198.51.100.2");
        CHECK(p.source_port == 12345); CHECK(p.destination_port == 8080);
        CHECK(p.tcp_sequence == 0x12000034); CHECK(p.tcp_ack == 0xab0000cd);
        CHECK(p.tcp_flag_bits == 0x12); CHECK(p.tcp_flags == "SYN ACK");
        CHECK(!p.malformed && !p.truncated && !p.fragmented);
        bool found = false;
        for (const auto& f : p.fields) if (f.section == "TCP" && f.name == "source_port") {
            CHECK(f.offset == (dlt == 1 ? 34u : dlt == 113 ? 36u : dlt == 276 ? 40u : dlt == 0 ? 24u : 20u));
            CHECK(f.length == 2 && f.value == "12345"); found = true;
        }
        CHECK(found);
    }
    for (unsigned tags : {1u, 2u}) CHECK(parse(link(v4(tcp()), 1, tags), 1).source_port == 12345);
    CHECK(parse(link(v4(tcp()), 1, 3), 1).malformed);
    CHECK(parse(link(v4(tcp()), 0, 0, true), 0).source_port == 12345);
    CHECK(parse(v4(tcp(), 6, 24)).destination_port == 8080);
    auto options = tcp(); options[12] = 0x60; options.resize(24);
    CHECK(!parse(v4(options)).malformed);
    CHECK(parse(Bytes(32), 999).protocol == "UNKNOWN");
}
void lengths_and_fragments() {
    auto b = v4(tcp()); b[0] = 0x44; CHECK(parse(b).malformed);
    b = v4(tcp()); put16(b, 2, 19); CHECK(parse(b).malformed);
    b = v4(tcp()); put16(b, 2, 20); auto p = parse(b); CHECK(p.malformed && p.source_port == 0);
    b = v4(tcp()); b[32] = 0x40; p = parse(b); CHECK(p.malformed && p.destination_port == 0);
    b = v4(tcp()); b[32] = 0xf0; p = parse(b); CHECK(p.malformed && p.source_port == 0);
    b = v4(tcp()); put16(b, 2, 100); p = parse(b); CHECK(p.truncated && !p.malformed);
    b = v4(tcp()); b.resize(30); p = parse(b); CHECK(p.truncated && p.source_port == 0 && !p.malformed);
    b = v4(tcp()); p = parse(b, 12, 100); CHECK(p.truncated);
    for (unsigned flags : {0x2000u, 1u, 0x2001u}) {
        b = v4(tcp("GET / HTTP/1.1\r\n")); put16(b, 6, flags); p = parse(b);
        CHECK(p.fragmented && p.source_port == 0 && p.http_line.empty()); CHECK(p.tcp_flag_bits == 0);
    }
    b = v4(tcp()); put16(b, 6, 0x4000); CHECK(!parse(b).fragmented);
    Bytes udp(8); put16(udp, 0, 53); put16(udp, 2, 5353); put16(udp, 4, 8);
    p = parse(v4(udp, 17)); CHECK(p.transport == "UDP" && p.source_port == 53 && !p.malformed);
    put16(udp, 4, 7); p = parse(v4(udp, 17)); CHECK(p.malformed && p.source_port == 0);
    put16(udp, 4, 9); p = parse(v4(udp, 17)); CHECK(p.malformed && p.source_port == 0);
    put16(udp, 4, 12); b = v4(udp, 17); put16(b, 2, 32); p = parse(b); CHECK(p.truncated && !p.malformed);
    Bytes icmp(8); icmp[0] = 8; p = parse(v4(icmp, 1)); CHECK(p.protocol == "ICMP" && p.source_port == 0);
    b = v4(Bytes(4), 1); CHECK(parse(b).malformed);
}
void ipv6() {
    for (int dlt : {1, 113, 276, 0, 12}) {
        auto p = parse(link(v6(tcp()), dlt), dlt); CHECK(p.network == "IPv6" && p.transport == "TCP");
        CHECK(p.source == "2001:db8::1" && p.destination == "2001:db8::2"); CHECK(!p.malformed && !p.truncated);
    }
    Bytes icmp(8); icmp[0] = 128;
    auto p = parse(v6(icmp, 58)); CHECK(p.protocol == "ICMPv6" && p.source_port == 0);
    auto b = v6(icmp, 58); b.resize(44); CHECK(parse(b).truncated);
    b = v6(icmp, 58); put16(b, 4, 0); CHECK(parse(b).malformed);
    b = v6(tcp(), 0); p = parse(b); CHECK(p.transport.empty() && p.protocol == "IPv6" && p.source_port == 0);
    b = v6(Bytes(8), 44); p = parse(b); CHECK(p.fragmented && p.source_port == 0);
    b.resize(44); CHECK(parse(b).truncated);
    b = v6(Bytes(4), 44); CHECK(parse(b).malformed);
}
void http_detection() {
    for (const std::string line : {"GET /hello?q=1 HTTP/1.1\r\n", "HTTP/1.0 200 OK\r\n", "PATCH / HTTP/1.1\r\n"}) {
        auto p = parse(v4(tcp(line, 9000))); CHECK(p.protocol == "HTTP" && p.transport == "TCP");
        CHECK(p.http_line == line.substr(0, line.size() - 2));
    }
    for (const std::string line : {"hello\r\n", "GET / HTTP/1.1", "GET / HTTP/1.1\n", "GET / HTTP/2.0\r\n", "HTTP/1.1 20 OK\r\n", "GET  HTTP/1.1\r\n"}) {
        auto p = parse(v4(tcp(line, 80))); CHECK(p.protocol == "TCP" && p.http_line.empty());
    }
    auto b = v4(tcp("GET / HTTP/1.1\r\n")); put16(b, 2, 40);
    CHECK(parse(b).protocol == "TCP"); // Entire visible line is Ethernet/IP padding.
    b = v4(tcp("GET / HTTP/1.1\r\n")); put16(b, 2, unsigned(b.size() - 1)); CHECK(parse(b).http_line.empty());
    b = v4(tcp("GET / HTTP/1.1\r\n")); b.pop_back(); CHECK(parse(b).http_line.empty());
    CHECK(parse(v6(tcp("GET / HTTP/1.1\r\n", 8888))).protocol == "HTTP");
}
void all_prefixes() {
    for (int dlt : {1, 113, 276, 0, 12}) {
        const auto full = link(v4(tcp("GET / HTTP/1.1\r\n"), 6, 24), dlt);
        for (std::size_t n = 0; n < full.size(); ++n) {
            Bytes prefix(full.begin(), full.begin() + n); auto p = parse(prefix, dlt, unsigned(full.size()));
            CHECK(p.truncated); CHECK(p.http_line.empty());
        }
        const auto six = link(v6(tcp()), dlt);
        for (std::size_t n = 0; n < six.size(); ++n) parse(Bytes(six.begin(), six.begin() + n), dlt, unsigned(six.size()));
    }
    for (unsigned n = 0; n < 22; ++n) parse(Bytes(n), 1);
    const auto tagged = link(v4(tcp()), 1, 2);
    for (std::size_t n = 0; n < tagged.size(); ++n) {
        CHECK(parse(Bytes(tagged.begin(), tagged.begin() + n), 1, unsigned(tagged.size())).truncated);
    }
    // Mutate every byte across all link types: exercise hostile lengths and discriminators.
    for (int dlt : {1, 113, 276, 0, 12}) {
        for (auto base : {link(v4(tcp("GET / HTTP/1.1\r\n")), dlt), link(v6(tcp()), dlt)}) {
            for (std::size_t i = 0; i < base.size(); ++i) {
                for (unsigned value : {0u, 15u, 255u}) {
                    auto mutated = base; mutated[i] = uint8_t(value); parse(mutated, dlt);
                }
            }
        }
    }
}
void dns_detection() {
    Bytes query{0x12,0x34,1,0,0,1,0,0,0,0,0,0,3,'w','w','w',7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    auto udp = [](const Bytes& payload, unsigned port = 53) {
        Bytes b(8); put16(b, 0, 12345); put16(b, 2, port); put16(b, 4, unsigned(payload.size() + 8));
        b.insert(b.end(), payload.begin(), payload.end()); return b;
    };
    auto p = parse(v4(udp(query), 17));
    CHECK(p.protocol == "DNS" && p.transport == "UDP");
    CHECK(p.summary.find("www.example.com") != std::string::npos);
    CHECK(parse(v6(udp(query), 17)).protocol == "DNS");
    CHECK(parse(v4(udp(query, 5353), 17)).protocol == "DNS");
    CHECK(parse(v4(udp(query, 9999), 17)).protocol == "UDP");
    auto response = query; response[2] = 0x81; response[3] = 0x80; response[7] = 1;
    const Bytes answer{0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,192,0,2,123};
    response.insert(response.end(), answer.begin(), answer.end());
    p = parse(v4(udp(response), 17)); CHECK(p.protocol == "DNS");
    bool address = false;
    for (const auto& f : p.fields) if (f.name == "address_ipv4") { CHECK(f.value == "192.0.2.123"); address = true; }
    CHECK(address);
    for (std::size_t n = 0; n < response.size(); ++n) {
        CHECK(parse(v4(udp(Bytes(response.begin(), response.begin() + n)), 17)).protocol != "DNS");
    }
    auto invalid = response; invalid[query.size() + 1] = uint8_t(query.size());
    CHECK(parse(v4(udp(invalid), 17)).protocol == "UDP"); // self pointer
    invalid = query; invalid[12] = 0xff; CHECK(parse(v4(udp(invalid), 17)).protocol == "UDP");
    invalid = query; invalid[4] = 0xff; CHECK(parse(v4(udp(invalid), 17)).protocol == "UDP");
    Bytes prefixed(2); put16(prefixed, 0, unsigned(query.size())); prefixed.insert(prefixed.end(), query.begin(), query.end());
    CHECK(parse(v4(tcp(std::string(prefixed.begin(), prefixed.end()), 53))).protocol == "DNS");
    auto padding = v4(udp(query), 17); padding.insert(padding.end(), 20, 0xff);
    CHECK(parse(padding).protocol == "DNS");
    for (std::size_t i = 0; i < response.size(); ++i) {
        auto mutated = response; mutated[i] = 0xff; parse(v4(udp(mutated), 17));
    }
}
int main() {
    links_and_fields(); lengths_and_fragments(); ipv6(); http_detection(); dns_detection(); all_prefixes();
    std::cout << "packet tests passed\n";
    return 0;
}
