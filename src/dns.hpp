#pragma once
#include "packet.hpp"
#include <arpa/inet.h>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace wirelens {
// DNS offsets are bounded by the UDP length (or one TCP DNS length prefix),
// never by Ethernet padding. Commit fields only after validating the whole PDU.
inline bool decode_dns(Packet& packet, std::size_t base, std::size_t length) {
    if (base > packet.bytes.size() || length > packet.bytes.size() - base || length < 12) return false;
    const auto* data = packet.bytes.data() + base;
    std::vector<Field> fields;
    auto check = [&](std::size_t pos, std::size_t count) {
        if (pos > length || count > length - pos) throw std::invalid_argument("DNS bounds");
    };
    auto u16 = [&](std::size_t pos) { check(pos, 2); return unsigned(data[pos]) * 256 + data[pos + 1]; };
    auto field = [&](const std::string& name, const std::string& value, std::size_t pos, std::size_t count) {
        fields.push_back({"DNS", name, value, base + pos, count});
    };
    auto name = [&](std::size_t& pos) {
        std::size_t at = pos, consumed = pos, wire_size = 1;
        bool jumped = false;
        std::string result;
        for (unsigned steps = 0; steps < 128; ++steps) {
            check(at, 1);
            auto n = data[at];
            if ((n & 0xc0) == 0xc0) {
                check(at, 2);
                auto target = std::size_t(n & 63) * 256 + data[at + 1];
                if (target < 12 || target >= at) throw std::invalid_argument("DNS compression pointer");
                if (!jumped) consumed = at + 2;
                jumped = true; at = target; continue;
            }
            if (n & 0xc0) throw std::invalid_argument("DNS label encoding");
            ++at;
            if (!n) { pos = jumped ? consumed : at; return result.empty() ? std::string(".") : result; }
            check(at, n); wire_size += n + 1;
            if (wire_size > 255) throw std::invalid_argument("DNS name length");
            if (!result.empty()) result += '.';
            for (unsigned i = 0; i < n; ++i) {
                auto c = data[at + i];
                if (c >= 33 && c <= 126 && c != '.' && c != '\\') result += char(c);
                else { std::ostringstream escaped; escaped << "\\x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(c); result += escaped.str(); }
            }
            at += n;
        }
        throw std::invalid_argument("DNS compression depth");
    };
    try {
        const auto flags = u16(2), questions = u16(4), answers = u16(6), authorities = u16(8), additional = u16(10);
        if ((flags & 0x0040) || questions + answers + authorities + additional > 256) return false;
        if (!(questions + answers + authorities + additional)) return false;
        field("transaction_id", std::to_string(u16(0)), 0, 2);
        field("response", flags & 0x8000 ? "true" : "false", 2, 2);
        field("response_code", std::to_string(flags & 15), 2, 2);
        field("questions", std::to_string(questions), 4, 2);
        field("answers", std::to_string(answers), 6, 2);
        std::size_t pos = 12;
        std::string first;
        for (unsigned i = 0; i < questions; ++i) {
            auto start = pos; auto text = name(pos);
            if (first.empty()) first = text;
            field("query_name", text, start, pos - start);
            field("query_type", std::to_string(u16(pos)), pos, 2);
            field("query_class", std::to_string(u16(pos + 2)), pos + 2, 2);
            pos += 4;
        }
        const auto records = answers + authorities + additional;
        for (unsigned i = 0; i < records; ++i) {
            auto start = pos; auto owner = name(pos);
            field("record_name", owner, start, pos - start);
            check(pos, 10); auto type = u16(pos), count = u16(pos + 8);
            field("record_type", std::to_string(type), pos, 2);
            field("record_class", std::to_string(u16(pos + 2)), pos + 2, 2);
            const auto ttl = (uint32_t(data[pos + 4]) << 24) | (uint32_t(data[pos + 5]) << 16) | (uint32_t(data[pos + 6]) << 8) | data[pos + 7];
            field("ttl", std::to_string(ttl), pos + 4, 4);
            pos += 10; check(pos, count);
            if (type == 1 || type == 28) {
                if (count != (type == 1 ? 4 : 16)) return false;
                char address[INET6_ADDRSTRLEN] = {};
                inet_ntop(type == 1 ? AF_INET : AF_INET6, data + pos, address, sizeof address);
                field(type == 1 ? "address_ipv4" : "address_ipv6", address, pos, count);
            } else if (type == 5 || type == 2 || type == 12) {
                auto cursor = pos; auto target = name(cursor);
                if (cursor != pos + count) return false;
                field("target_name", target, pos, count);
            }
            pos += count;
        }
        if (pos != length) return false;
        packet.protocol = "DNS";
        packet.summary = std::string(flags & 0x8000 ? "DNS response " : "DNS query ") + first + " id=" + std::to_string(u16(0));
        packet.fields.insert(packet.fields.end(), fields.begin(), fields.end());
        return true;
    } catch (const std::invalid_argument&) { return false; }
}
}
