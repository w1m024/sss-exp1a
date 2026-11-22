#pragma once
#include "packet.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <optional>
#include <string_view>

namespace wirelens::http_stream {
constexpr std::size_t limit = 256 * 1024;
// 每个方向独立按 TCP 序号保存字节和来源包。
struct Direction {
    std::optional<uint32_t> base;
    std::string bytes;
    std::vector<const Packet*> source;
    std::optional<uint32_t> fin_offset;
    const Packet* fin = nullptr;
    bool conflicting_fin = false;
    bool limited = false, conflict = false, truncated = false;

    void append(const Packet& p) {
        truncated |= p.truncated;
        if (!base) return;
        uint32_t offset = p.tcp_sequence + ((p.tcp_flag_bits & 2) ? 1 : 0) - *base;
        if ((p.tcp_flag_bits & 5) == 1 && !p.truncated) {
            const uint32_t end = offset + p.tcp_payload_size;
            if (fin_offset && *fin_offset != end) conflicting_fin = true;
            if (!fin) { fin_offset = end; fin = &p; }
        }
        if (!p.tcp_payload_size) return;
        if (offset >= limit) { limited = true; return; }
        const auto size = std::min(p.tcp_payload_size, limit - offset);
        limited |= size != p.tcp_payload_size;
        if (source.size() < offset + size) {
            source.resize(offset + size);
            bytes.resize(offset + size);
        }
        for (std::size_t i = 0; i < size; ++i) {
            const auto index = offset + i;
            const char b = char(p.bytes[p.tcp_payload_offset + i]);
            if (!source[index]) { source[index] = &p; bytes[index] = b; }
            else if (bytes[index] != b) conflict = true;
        }
    }
    // FIN 的序号必须紧接完整载荷，才能用来确定正文结束位置。
    const Packet* closing_packet(std::size_t prefix_size) const {
        return fin_offset == prefix_size && bytes.size() == prefix_size &&
            !limited && !conflict && !truncated && !conflicting_fin ? fin : nullptr;
    }
    // 遇到缺口时，只返回缺口之前连续的数据。
    std::string_view prefix() const {
        if (conflict) return {};
        return std::string_view(bytes).substr(0, std::find(source.begin(), source.end(), nullptr) - source.begin());
    }
};
struct Message {
    std::string_view line, method, target, headers;
    const char* framing = "none";
    unsigned status = 0;
    std::size_t end = 0, body_size = 0;
};
inline bool token(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            std::string_view("!#$%&'*+-.^`_|~").find(c) != std::string_view::npos;
    });
}
inline bool version(std::string_view s) { return s == "HTTP/1.1" || s == "HTTP/1.0"; }
inline std::string_view trim(std::string_view value) {
    const auto start = value.find_first_not_of(" \t");
    if (start == value.npos) return {};
    return value.substr(start, value.find_last_not_of(" \t") - start + 1);
}
inline bool field_line(std::string_view line) {
    const auto colon = line.find(':');
    return colon != line.npos && token(line.substr(0, colon)) &&
        std::all_of(line.begin() + colon + 1, line.end(), [](unsigned char c) {
            return c == '\t' || (c >= 32 && c != 127);
        });
}
inline bool chunks(std::string_view bytes, std::size_t pos, Message& m, const char*& issue) {
    for (;;) {
        const auto end = bytes.find("\r\n", pos);
        if (end == bytes.npos) return false;
        if (end - pos > 8192) { issue = "analysis_limit"; return false; }
        const auto line = bytes.substr(pos, end - pos);
        const auto hex = trim(line.substr(0, line.find(';')));
        if (hex.empty()) { issue = "invalid_framing"; return false; }
        std::size_t size = 0;
        const auto parsed = std::from_chars(hex.data(), hex.data() + hex.size(), size, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != hex.data() + hex.size()) {
            issue = "invalid_framing"; return false;
        }
        pos = end + 2;
        if (!size) {
            const auto trailers = pos;
            for (;;) {
                const auto next = bytes.find("\r\n", pos);
                if (next == bytes.npos) return false;
                if (next - trailers > 32768) { issue = "analysis_limit"; return false; }
                if (next == pos) { m.end = pos + 2; return true; }
                if (!field_line(bytes.substr(pos, next - pos))) { issue = "invalid_framing"; return false; }
                pos = next + 2;
            }
        }
        if (size > bytes.size() - pos || bytes.size() - pos - size < 2) return false;
        pos += size;
        if (bytes.substr(pos, 2) != "\r\n") { issue = "invalid_framing"; return false; }
        m.body_size += size;
        pos += 2;
    }
}
inline std::optional<Message> parse(std::string_view bytes, std::size_t at, bool response, const char*& issue, std::string_view method = {}, bool closed = false) {
    issue = "incomplete_message";
    if (at >= bytes.size()) return {};
    auto header = bytes.substr(at, 32768);
    const auto split = header.find("\r\n\r\n"), line_end = header.find("\r\n");
    if (split == header.npos || line_end > split) {
        if (header.size() == 32768) issue = "analysis_limit";
        return {};
    }
    issue = "invalid_framing";
    Message m;
    m.line = header.substr(0, line_end);
    if (line_end < split) m.headers = header.substr(line_end + 2, split - line_end - 2);
    if (!std::all_of(m.line.begin(), m.line.end(), [](unsigned char c) { return c >= 32 && c <= 126; })) return {};
    if (response) {
        if (m.line.size() < 13 || !version(m.line.substr(0,8)) || m.line[8] != ' ' || m.line[12] != ' ') return {};
        auto status = m.line.substr(9,3);
        auto parsed = std::from_chars(status.data(), status.data()+3, m.status);
        if (parsed.ec != std::errc{} || parsed.ptr != status.data()+3 || m.status < 100 || m.status > 599) return {};
    } else {
        const auto first = m.line.find(' '), last = m.line.rfind(' ');
        if (first == m.line.npos || last <= first + 1 || !version(m.line.substr(last+1))) return {};
        m.method = m.line.substr(0,first);
        m.target = m.line.substr(first+1,last-first-1);
        if (!token(m.method) || m.line.substr(first+1,last-first-1).find(' ') != m.line.npos) return {};
    }
    std::optional<std::size_t> length;
    bool transfer_encoding = false;
    bool chunked = false;
    for (std::size_t pos = line_end + 2; pos < split; ) {
        const auto next = header.find("\r\n", pos);
        if (next > split) return {};
        auto field = header.substr(pos,next-pos);
        const auto colon = field.find(':');
        if (!field_line(field)) return {};
        auto name = std::string(field.substr(0,colon));
        for (auto& c : name) if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        auto value = field.substr(colon+1);
        if (name == "transfer-encoding") {
            if (transfer_encoding) return {};
            transfer_encoding = true;
            auto coding = std::string(trim(value));
            for (auto& c : coding) if (c >= 'A' && c <= 'Z') c += 'a'-'A';
            chunked = coding == "chunked";
        }
        if (name == "content-length") {
            const auto begin = value.find_first_not_of(" \t"), end = value.find_last_not_of(" \t");
            if (begin == value.npos || length) return {};
            value = value.substr(begin,end-begin+1);
            std::size_t n = 0;
            const auto parsed = std::from_chars(value.data(),value.data()+value.size(),n);
            if (parsed.ec != std::errc{} || parsed.ptr != value.data()+value.size()) return {};
            length = n;
        }
        pos = next+2;
    }
    const bool no_body = response && (method == "HEAD" || m.status < 200 || m.status == 204 || m.status == 304);
    const auto payload = at + split + 4;
    if (transfer_encoding && length) return {};
    if (!no_body && transfer_encoding) {
        const auto wire_version = response ? m.line.substr(0, 8) : m.line.substr(m.line.size() - 8);
        if (!chunked || wire_version == "HTTP/1.0") {
            issue = "unsupported_framing"; return {};
        }
        m.framing = "chunked";
        issue = "incomplete_message";
        if (!chunks(bytes, payload, m, issue)) return {};
        return m;
    }
    if (!no_body && response && !length) {
        if (!closed) { issue = "awaiting_close"; return {}; }
        m.framing = "close-delimited";
        m.body_size = bytes.size() - payload;
        m.end = bytes.size();
        return m;
    }
    m.body_size = no_body ? 0 : length.value_or(0);
    if (!no_body && length) m.framing = "content-length";
    if (m.body_size > bytes.size()-payload) { issue = "incomplete_message"; return {}; }
    m.end = payload + m.body_size;
    return m;
}
}
