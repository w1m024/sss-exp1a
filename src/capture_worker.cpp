#include "ipc.hpp"
#include "json.hpp"
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <chrono>
#include <iostream>
#include <memory>
#include <poll.h>
#include <string>
#include <sys/socket.h>

namespace {
volatile sig_atomic_t stopping = 0;
void stop(int) { stopping = 1; }
using Devices = std::unique_ptr<pcap_if_t, decltype(&pcap_freealldevs)>;
using Capture = std::unique_ptr<pcap_t, decltype(&pcap_close)>;
bool error(const char* text) {
    // Use fixed diagnostics: filter expressions and packet data never reach stderr.
    std::string s(text);
    if (s.size() > 4096) s.resize(4096);
    return wirelens::ipc::write_message(STDOUT_FILENO, wirelens::ipc::Error,
                                       std::vector<uint8_t>(s.begin(), s.end()));
}
}
int main(int argc, char** argv) {
    using namespace wirelens::ipc;
    const bool listing = argc == 2 && std::string(argv[1]) == "--interfaces";
    const bool capturing = argc == 4 && std::string(argv[1]) == "--capture";
    if (!listing && !capturing) {
        std::cerr << "Usage: wirelens-capture --interfaces | --capture INTERFACE FILTER\n";
        return 2;
    }
    try {
        auto fail = [&](const char* message) { if (capturing) error(message); else std::cerr << message << '\n'; return 1; };
        if (capturing && std::strlen(argv[3]) > 1024) return fail("Filter exceeds 1024 bytes");
        char errbuf[PCAP_ERRBUF_SIZE]{};
        pcap_if_t* raw = nullptr;
        if (pcap_findalldevs(&raw, errbuf) != 0) return fail("Cannot enumerate capture interfaces");
        Devices devices(raw, pcap_freealldevs);
        if (listing) {
            std::cout << "{\"interfaces\":[";
            bool first = true;
            for (auto* d = raw; d; d = d->next) {
                if (!d->name) continue;
                if (!first) std::cout << ',';
                first = false;
                std::cout << "{\"name\":" << wirelens::json_string(d->name)
                          << ",\"description\":" << wirelens::json_string(d->description ? d->description : "")
                          << ",\"addresses\":[";
                bool first_address = true;
                for (auto* a = d->addresses; a; a = a->next) {
                    if (!a->addr) continue;
                    char address[INET6_ADDRSTRLEN]{};
                    const void* value = nullptr;
                    const int family = a->addr->sa_family;
                    if (family == AF_INET) value = &reinterpret_cast<const sockaddr_in*>(a->addr)->sin_addr;
                    else if (family == AF_INET6) value = &reinterpret_cast<const sockaddr_in6*>(a->addr)->sin6_addr;
                    if (!value || !inet_ntop(family, value, address, sizeof(address))) continue;
                    if (!first_address) std::cout << ',';
                    first_address = false;
                    std::cout << wirelens::json_string(address);
                }
                std::cout << "],\"loopback\":" << ((d->flags & PCAP_IF_LOOPBACK) ? "true" : "false") << '}';
            }
            std::cout << "]}\n";
            return std::cout ? 0 : 1;
        }
        bool allowed = false;
        for (auto* d = raw; d; d = d->next)
            if (d->name && std::strcmp(d->name, argv[2]) == 0) allowed = true;
        if (!allowed) return fail("Unknown capture interface");
        struct sigaction action{};
        action.sa_handler = stop;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, nullptr) || sigaction(SIGINT, &action, nullptr))
            return fail("Cannot install signal handlers");
        Capture capture(pcap_open_live(argv[2], 65535, 0, 100, errbuf), pcap_close);
        if (!capture) return fail("Cannot open capture interface (CAP_NET_RAW required)");
        bpf_program program{};
        if (pcap_compile(capture.get(), &program, argv[3], 1, PCAP_NETMASK_UNKNOWN) < 0)
            return fail("Cannot compile capture filter");
        const int filter_result = pcap_setfilter(capture.get(), &program);
        pcap_freecode(&program);
        if (filter_result < 0) return fail("Cannot install capture filter");
        if (pcap_setnonblock(capture.get(), 1, errbuf) < 0) return fail("Cannot enable nonblocking capture");
        std::vector<uint8_t> ready;
        const int datalink = pcap_datalink(capture.get());
        if (datalink < 0) return fail("Cannot determine datalink");
        put_u32(ready, static_cast<uint32_t>(datalink));
        if (!write_message(1, Ready, ready)) return 1;
        auto stats = [&]() {
            pcap_stat s{};
            const bool supported = pcap_stats(capture.get(), &s) == 0;
            std::vector<uint8_t> p;
            put_u32(p, supported ? s.ps_recv : 0); put_u32(p, supported ? s.ps_drop : 0);
            put_u32(p, supported ? s.ps_ifdrop : 0); put_u32(p, supported ? 1 : 0);
            return write_message(1, Stats, p);
        };
        auto last = std::chrono::steady_clock::now();
        const int fd = pcap_get_selectable_fd(capture.get());
        int result = 0;
        while (!stopping) {
            // Bounded batches keep signals and statistics responsive under heavy traffic.
            for (int i = 0; i < 64 && !stopping; ++i) {
                pcap_pkthdr* h = nullptr;
                const u_char* bytes = nullptr;
                const int n = pcap_next_ex(capture.get(), &h, &bytes);
                if (n == 0) break;
                if (n == -2) { stopping = 1; break; }
                if (n < 0) { error("Capture read failed"); result = 1; stopping = 1; break; }
                if (!h || !bytes || h->caplen > 65535 || h->caplen > h->len ||
                    h->ts.tv_sec < 0 || h->ts.tv_usec < 0 || h->ts.tv_usec >= 1000000 ||
                    static_cast<uint64_t>(h->ts.tv_sec) > (UINT64_MAX - 999999) / 1000000) {
                    error("Invalid capture record"); result = 1; stopping = 1; break;
                }
                std::vector<uint8_t> p;
                p.reserve(16 + h->caplen);
                put_u64(p, static_cast<uint64_t>(h->ts.tv_sec) * 1000000 + h->ts.tv_usec);
                put_u32(p, h->len); put_u32(p, h->caplen);
                p.insert(p.end(), bytes, bytes + h->caplen);
                if (!write_message(1, Packet, p)) return 1;
            }
            const auto now = std::chrono::steady_clock::now();
            if (now - last >= std::chrono::seconds(1)) {
                if (!stats()) return 1;
                last = now;
            }
            if (stopping) break;
            pollfd poll_fd{fd, POLLIN, 0};
            const int n = poll(fd >= 0 ? &poll_fd : nullptr, fd >= 0 ? 1 : 0, 100);
            if ((n < 0 && errno != EINTR) || (n > 0 && (poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)))) {
                error("Capture poll failed"); result = 1; break;
            }
        }
        if (!stats()) return 1;
        return result;
    } catch (const std::exception&) {
        if (capturing) { try { error("Capture helper failure"); } catch (...) {} }
        else std::cerr << "Interface enumeration failed\n";
        return 1;
    }
}
