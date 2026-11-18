#pragma once
#include <algorithm>
#include <cstdint>
#include <arpa/inet.h>
#include <unistd.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace wirelens {
struct ProcessOwner {
    unsigned pid = 0, uid = 0;
    std::string name, start_ticks;
    std::string key() const { return std::to_string(pid) + ":" + start_ticks; }
};
class ProcessTracker {
    using Owners = std::vector<ProcessOwner>;
    std::map<std::string, Owners> sockets_;
    std::chrono::steady_clock::time_point refreshed_{};
    static std::string endpoint(const std::string& address, unsigned port) {
        return (address.find(':') == std::string::npos ? address : "[" + address + "]") + ":" + std::to_string(port);
    }
    static std::string socket_endpoint(const std::string& value, int family) {
        const auto colon = value.find(':');
        if (colon == std::string::npos || colon != (family == AF_INET ? 8u : 32u)) return {};
        unsigned char bytes[16] = {};
        try {
            // proc tcp addresses use native-endian 32-bit words, including IPv6.
            for (std::size_t i = 0; i < colon; i += 8) {
                auto word = uint32_t(std::stoul(value.substr(i, 8), nullptr, 16));
                for (unsigned j = 0; j < 4; ++j) bytes[i / 2 + j] = uint8_t(word >> (8 * j));
            }
            char text[INET6_ADDRSTRLEN] = {};
            if (!inet_ntop(family, bytes, text, sizeof text)) return {};
            return endpoint(text, unsigned(std::stoul(value.substr(colon + 1), nullptr, 16)));
        } catch (const std::exception&) { return {}; }
    }
    static std::string tuple(const std::string& a, const std::string& b) { return a < b ? a + "|" + b : b + "|" + a; }
public:
    void reset() { sockets_.clear(); refreshed_ = {}; }
    Owners lookup(const std::string& source, unsigned source_port, const std::string& destination, unsigned destination_port) {
        const auto now = std::chrono::steady_clock::now();
        if (now - refreshed_ >= std::chrono::milliseconds(100)) { refresh(); refreshed_ = now; }
        auto it = sockets_.find(tuple(endpoint(source, source_port), endpoint(destination, destination_port)));
        return it == sockets_.end() ? Owners{} : it->second;
    }
    void refresh() {
        sockets_.clear();
        std::map<std::string, std::string> inode_tuple;
        for (const auto& item : {std::pair<const char*, int>{"/proc/net/tcp", AF_INET}, {"/proc/net/tcp6", AF_INET6}}) {
            std::ifstream input(item.first); std::string line; std::getline(input, line);
            for (unsigned count = 0; count < 65536 && std::getline(input, line); ++count) {
                std::istringstream row(line); std::vector<std::string> cells; std::string cell;
                while (row >> cell) cells.push_back(cell);
                if (cells.size() < 10 || cells[3] == "0A" || cells[9] == "0") continue;
                auto a = socket_endpoint(cells[1], item.second), b = socket_endpoint(cells[2], item.second);
                if (!a.empty() && !b.empty()) inode_tuple[cells[9]] = tuple(a, b);
            }
        }
        std::error_code error;
        unsigned processes = 0, descriptors = 0;
        for (const auto& entry : std::filesystem::directory_iterator("/proc", error)) {
            if (++processes > 32768 || descriptors > 131072) break;
            auto id = entry.path().filename().string();
            if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) continue;
            // Ordinary-user mode deliberately avoids privileges for other users.
            std::ifstream status(entry.path() / "status"); std::string line; unsigned uid = ~0u;
            while (std::getline(status, line)) if (line.rfind("Uid:", 0) == 0) { std::istringstream(line.substr(4)) >> uid; break; }
            if (uid != getuid()) continue;
            std::ifstream stat(entry.path() / "stat"); std::getline(stat, line);
            auto close = line.rfind(')'); if (close == std::string::npos) continue;
            std::istringstream columns(line.substr(close + 1)); std::string start;
            for (unsigned i = 3; i <= 22; ++i) if (!(columns >> start)) { start.clear(); break; }
            if (start.empty()) continue;
            std::ifstream comm(entry.path() / "comm"); std::string name; std::getline(comm, name); name.resize(std::min<std::size_t>(name.size(), 128));
            ProcessOwner owner{unsigned(std::stoul(id)), uid, name, start};
            std::filesystem::directory_iterator fds(entry.path() / "fd", std::filesystem::directory_options::skip_permission_denied, error);
            while (!error && fds != std::filesystem::directory_iterator{}) {
                if (++descriptors > 131072) break;
                auto link = std::filesystem::read_symlink(fds->path(), error).string();
                error.clear(); fds.increment(error);
                if (link.rfind("socket:[", 0) != 0 || link.back() != ']') continue;
                auto found = inode_tuple.find(link.substr(8, link.size() - 9));
                if (found == inode_tuple.end()) continue;
                auto& owners = sockets_[found->second];
                bool duplicate = false;
                for (const auto& existing : owners) if (existing.key() == owner.key()) duplicate = true;
                if (!duplicate && owners.size() < 32) owners.push_back(owner);
            }
            error.clear();
        }
    }
};
}
