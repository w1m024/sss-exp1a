#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <algorithm>
#include <cerrno>
#include <charconv>
#include <csignal>
#include <iostream>
#include <cstring>
#include <vector>
#include <memory>
#include <string_view>
#include "tcp_owner_event.h"

static volatile std::sig_atomic_t stop = 0;
static void interrupt(int) { stop = 1; }
static int64_t micros(clockid_t clock) {
    timespec t{};
    clock_gettime(clock, &t);
    return int64_t(t.tv_sec) * 1000000 + t.tv_nsec / 1000;
}
static std::string address(int family, const unsigned char* bytes) {
    char text[INET6_ADDRSTRLEN]{};
    if (family == AF_INET6 && std::all_of(bytes, bytes + 10, [](auto b) { return b == 0; })
        && bytes[10] == 255 && bytes[11] == 255) { family = AF_INET; bytes += 12; }
    return inet_ntop(family, bytes, text, sizeof(text)) ? text : "";
}
static int output(void*, void* data, size_t size) {
    if (size != sizeof(tcp_owner_event)) return 0;
    const auto& e = *static_cast<const tcp_owner_event*>(data);
    std::string name(e.name, strnlen(e.name, sizeof(e.name)));
    for (char& ch : name) if (static_cast<unsigned char>(ch) < 32) ch = ' ';
    const auto when = micros(CLOCK_REALTIME) - micros(CLOCK_MONOTONIC) + e.time_ns / 1000;
    const auto hz = sysconf(_SC_CLK_TCK);
    const auto ticks = e.start_ns / 1000000000 * hz + e.start_ns % 1000000000 * hz / 1000000000;
    std::cout << when << ' ' << e.uid << ' ' << e.pid << ' ' << ticks << ' '
        << address(e.family, e.local) << ' ' << e.local_port << ' '
        << address(e.family, e.remote) << ' ' << ntohs(e.remote_port) << ' ' << name << std::endl;
    return std::cout ? 0 : -EIO;
}
int main(int argc, char** argv) {
    unsigned uid;
    const auto arg = argc == 3 ? std::string_view(argv[2]) : std::string_view{};
    if (arg.empty()) { std::cerr << "Usage: wirelens-tcp-owner BPF_OBJECT UID\n"; return 2; }
    const auto parsed = std::from_chars(arg.data(), arg.data() + arg.size(), uid);
    if (parsed.ec != std::errc{} || parsed.ptr != arg.data() + arg.size()) return 2;
    auto* raw = bpf_object__open_file(argv[1], nullptr);
    if (libbpf_get_error(raw) || !raw) return 1;
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> object(raw, bpf_object__close);
    bpf_map* config = nullptr;
    bpf_map* map;
    bpf_object__for_each_map(map, raw)
        if (std::string_view(bpf_map__name(map)).find(".rodata") != std::string_view::npos) config = map;
    struct stat netns{}, pidns{};
    if (stat("/proc/self/ns/net", &netns) || stat("/proc/self/ns/pid", &pidns)) return 1;
    tcp_owner_config settings{pidns.st_dev, pidns.st_ino, uid, static_cast<__u32>(netns.st_ino)};
    if (!config || bpf_map__set_initial_value(config, &settings, sizeof(settings)) || bpf_object__load(raw)) return 1;
    using Link = std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)>;
    std::vector<Link> links;
    bpf_program* program;
    bpf_object__for_each_program(program, raw) {
        auto* link = bpf_program__attach(program);
        if (!link || libbpf_get_error(link)) return 1;
        links.emplace_back(link, bpf_link__destroy);
    }
    auto* events = ring_buffer__new(bpf_object__find_map_fd_by_name(raw, "events"), output, nullptr, nullptr);
    if (!events || libbpf_get_error(events)) return 1;
    std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)> ring(events, ring_buffer__free);
    std::signal(SIGTERM, interrupt);
    std::signal(SIGINT, interrupt);
    std::cerr << "TCP owner probe ready\n";
    while (!stop) {
        int result = ring_buffer__poll(events, 100);
        if (result < 0 && result != -EINTR) return 1;
    }
}
