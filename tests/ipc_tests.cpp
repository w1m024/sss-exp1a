#include "../src/ipc.hpp"
#include <iostream>
#include <functional>
#include <sys/socket.h>
#include <thread>

namespace {
void check(bool b) { if (!b) throw std::runtime_error("test assertion failed"); }
struct Pipe {
    int f[2];
    Pipe() { if (pipe(f)) throw std::runtime_error("pipe failed"); }
    ~Pipe() { for (int fd : f) if (fd >= 0) close(fd); }
    void finish() { close(f[1]); f[1] = -1; }
};
void malformed(std::vector<uint8_t> bytes) {
    Pipe p;
    check(write(p.f[1], bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
    p.finish();
    wirelens::ipc::Message m;
    bool threw = false;
    try { wirelens::ipc::read_message(p.f[0], m); } catch (const std::runtime_error&) { threw = true; }
    check(threw);
}
}
int main() {
    using namespace wirelens::ipc;
    try {
        std::vector<uint8_t> data;
        put_u32(data, 0x12345678); put_u64(data, 0x0123456789abcdefULL);
        check(data[0] == 0x12 && data[4] == 1);
        check(get_u32(data, 0) == 0x12345678 && get_u64(data, 4) == 0x0123456789abcdefULL);
        {
            Pipe p;
            for (Type t : {Ready, Packet, Stats, Error}) check(write_message(p.f[1], t, data));
            check(write_message(p.f[1], Ready, {}));
            p.finish();
            Message m;
            for (Type t : {Ready, Packet, Stats, Error}) {
                check(read_message(p.f[0], m)); check(m.type == t && m.payload == data);
            }
            check(read_message(p.f[0], m) && m.payload.empty());
            check(!read_message(p.f[0], m));
        }
        auto header = [](uint32_t magic_value, uint32_t length) {
            std::vector<uint8_t> h;
            put_u32(h, magic_value); put_u32(h, Packet); put_u32(h, length); return h;
        };
        malformed(header(0, 0));
        malformed(header(magic, max_payload + 1));
        for (size_t size = 1; size < 12; ++size) {
            auto h = header(magic, 0); h.resize(size); malformed(h);
        }
        auto h = header(magic, 4); h.push_back(1); malformed(h);
        {
            Pipe p; p.finish(); Message m; check(!read_message(p.f[0], m));
        }
        {
            int sockets[2];
            check(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
            std::vector<uint8_t> large(max_payload, 0xa5);
            bool sent = false;
            std::thread writer([&] { sent = write_message(sockets[0], Packet, large); close(sockets[0]); });
            Message m;
            const bool received = read_message(sockets[1], m);
            writer.join();
            close(sockets[1]);
            check(sent && received && m.payload == large);
        }
        {
            bool threw = false;
            try { get_u64(data, static_cast<size_t>(-1)); }
            catch (const std::runtime_error&) { threw = true; }
            check(threw);
            threw = false;
            Message m;
            try { read_message(-1, m); }
            catch (const std::runtime_error&) { threw = true; }
            check(threw);
        }
        {
            Pipe p; close(p.f[0]); p.f[0] = -1;
            check(!write_message(p.f[1], Packet, {})); // 必须能处理 SIGPIPE。
        }
        {
            bool threw = false;
            try { write_message(-1, Packet, std::vector<uint8_t>(max_payload + 1)); }
            catch (const std::runtime_error&) { threw = true; }
            check(threw);
        }
        std::cout << "IPC tests passed: roundtrip, endian, badmagic, oversize, truncation, EOF, SIGPIPE\n";
        return 0;
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
