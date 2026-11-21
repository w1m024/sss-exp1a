#pragma once

#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <pthread.h>
#include <stdexcept>
#include <utility>
#include <vector>
#include <unistd.h>

namespace wirelens::ipc {
// 所有整数（包括消息头）均为无符号大端序。
inline constexpr uint32_t magic = 0x574c5043; // WLPC
inline constexpr uint32_t max_payload = 65536 + 64;
enum Type : uint32_t { Ready = 1, Packet = 2, Stats = 3, Error = 4 };
struct Message { Type type; std::vector<uint8_t> payload; };
inline void put_u32(std::vector<uint8_t>& v, uint32_t n) {
    for (int s = 24; s >= 0; s -= 8) v.push_back(static_cast<uint8_t>(n >> s));
}
inline void put_u64(std::vector<uint8_t>& v, uint64_t n) {
    put_u32(v, static_cast<uint32_t>(n >> 32)); put_u32(v, static_cast<uint32_t>(n));
}
inline uint32_t get_u32(const std::vector<uint8_t>& v, size_t p) {
    if (p > v.size() || v.size() - p < 4) throw std::runtime_error("IPC short integer");
    uint32_t n = 0;
    for (size_t i = 0; i < 4; ++i) n = (n << 8) | v[p + i];
    return n;
}
inline uint64_t get_u64(const std::vector<uint8_t>& v, size_t p) {
    if (p > v.size() || v.size() - p < 8) throw std::runtime_error("IPC short integer");
    return (uint64_t(get_u32(v, p)) << 32) | get_u32(v, p + 4);
}
inline bool read_exact(int fd, uint8_t* p, size_t n, bool eof_allowed) {
    size_t done = 0;
    while (done < n) {
        const ssize_t r = ::read(fd, p + done, n - done);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0) throw std::runtime_error("IPC read failed");
        if (r == 0) {
            if (done == 0 && eof_allowed) return false;
            throw std::runtime_error("IPC truncated frame");
        }
        done += static_cast<size_t>(r);
    }
    return true;
}
inline bool read_message(int fd, Message& m) {
    std::vector<uint8_t> h(12);
    if (!read_exact(fd, h.data(), h.size(), true)) return false;
    const auto t = get_u32(h, 4), n = get_u32(h, 8);
    if (get_u32(h, 0) != magic) throw std::runtime_error("IPC bad magic");
    if (t < Ready || t > Error) throw std::runtime_error("IPC invalid type");
    if (n > max_payload) throw std::runtime_error("IPC oversized frame");
    std::vector<uint8_t> payload(n);
    read_exact(fd, payload.data(), n, false);
    m = {static_cast<Type>(t), std::move(payload)};
    return true;
}
inline bool write_message(int fd, Type t, const std::vector<uint8_t>& payload) {
    if (payload.size() > max_payload || t < Ready || t > Error)
        throw std::runtime_error("IPC invalid outgoing frame");
    // 只在当前线程屏蔽 SIGPIPE，保留原有待处理信号。
    sigset_t mask, old, pending;
    sigemptyset(&mask); sigaddset(&mask, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &mask, &old) != 0)
        throw std::runtime_error("IPC signal mask failed");
    sigpending(&pending);
    const bool was_pending = sigismember(&pending, SIGPIPE) == 1;
    bool ok = true;
    int failure = 0;
    // 信号屏蔽期间不分配内存。
    uint8_t header[12];
    const uint32_t fields[] = {magic, static_cast<uint32_t>(t), static_cast<uint32_t>(payload.size())};
    for (size_t i = 0; i < 3; ++i)
        for (size_t j = 0; j < 4; ++j) header[4*i+j] = static_cast<uint8_t>(fields[i] >> (24-8*j));
    for (int part = 0; part < 2 && ok; ++part) {
        const uint8_t* p = part == 0 ? header : payload.data();
        size_t remaining = part == 0 ? sizeof(header) : payload.size();
        while (remaining) {
            const ssize_t r = ::write(fd, p, remaining);
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { failure = r < 0 ? errno : EIO; ok = false; break; }
            p += r; remaining -= static_cast<size_t>(r);
        }
    }
    if (failure == EPIPE && !was_pending) {
        timespec zero{};
        while (sigtimedwait(&mask, nullptr, &zero) < 0 && errno == EINTR) {}
    }
    pthread_sigmask(SIG_SETMASK, &old, nullptr);
    return ok;
}
} // namespace wirelens::ipc
