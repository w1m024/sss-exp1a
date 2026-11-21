#include "capture.hpp"
#include "http_stream.hpp"
#include "ipc.hpp"
#include "json.hpp"
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <spawn.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <algorithm>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <set>
#include <limits>
#include <stdexcept>
#include <sstream>
#include <chrono>

extern char **environ;
namespace wirelens {
static std::string lower(std::string value) {
    for (char& c : value) c = char(std::tolower(static_cast<unsigned char>(c)));
    return value;
}
static std::string owners_json(const std::vector<ProcessOwner>& owners) {
    std::string result = "[";
    for (const auto& owner : owners) {
        if (result.size() > 1) result += ',';
        result += "{\"key\":" + json_string(owner.key()) + ",\"pid\":" + std::to_string(owner.pid)
            + ",\"uid\":" + std::to_string(owner.uid) + ",\"name\":" + json_string(owner.name)
            + ",\"start_ticks\":" + json_string(owner.start_ticks) + '}';
    }
    return result + ']';
}
static std::string endpoint(const std::string& address, uint16_t port) {
    return (address.find(':') != std::string::npos ? "[" + address + "]" : address)
        + ":" + std::to_string(port);
}
static ipc::Message handshake(int fd) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    auto read = [&](std::vector<uint8_t>& buffer) {
        std::size_t offset = 0;
        while (offset < buffer.size()) {
            auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) throw std::runtime_error("Capture helper handshake timed out");
            pollfd p{fd, POLLIN, 0};
            int result = poll(&p, 1, int(remaining));
            if (result < 0 && errno == EINTR) continue;
            if (result <= 0) throw std::runtime_error("Capture helper handshake timed out");
            auto n = ::read(fd, buffer.data() + offset, buffer.size() - offset);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("Capture helper exited during handshake");
            offset += std::size_t(n);
        }
    };
    std::vector<uint8_t> header(12); read(header);
    auto type = ipc::get_u32(header, 4), length = ipc::get_u32(header, 8);
    if (ipc::get_u32(header, 0) != ipc::magic ||
        (type != ipc::Ready && type != ipc::Error) || length > 4096)
        throw std::runtime_error("Invalid capture handshake header");
    ipc::Message message{static_cast<ipc::Type>(type), std::vector<uint8_t>(length)};
    read(message.payload);
    return message;
}
std::string interfaces_json() {
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *all = nullptr;
    if (pcap_findalldevs(&all, error) < 0) throw std::runtime_error(error);
    std::string result = "{\"interfaces\":[";
    bool first = true;
    for (auto *device = all; device; device = device->next) {
        if (!first) result += ',';
        first = false;
        result += "{\"name\":" + json_string(device->name) + ",\"description\":"
            + json_string(device->description ? device->description : device->name)
            + ",\"loopback\":" + ((device->flags & PCAP_IF_LOOPBACK) ? "true" : "false")
            + ",\"addresses\":[";
        bool first_address = true;
        for (auto *a = device->addresses; a; a = a->next) {
            if (!a->addr || (a->addr->sa_family != AF_INET && a->addr->sa_family != AF_INET6)) continue;
            char buffer[NI_MAXHOST];
            auto length = a->addr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
            if (getnameinfo(a->addr, length, buffer, sizeof(buffer), nullptr, 0, NI_NUMERICHOST)) continue;
            if (!first_address) result += ',';
            first_address = false;
            result += json_string(buffer);
        }
        result += "]}";
    }
    pcap_freealldevs(all);
    return result + "]}";
}
Capture::Capture(std::string helper, std::size_t capacity, std::size_t limit)
    : helper_(std::move(helper)), capacity_(std::max<std::size_t>(1, capacity)),
      memory_limit_(std::max<std::size_t>(131072, limit)) {}
Capture::~Capture() { stop(); }
void Capture::start(const std::string& device, const std::string& filter, const std::string& requested_filter) {
    std::lock_guard<std::mutex> operation(operation_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ == "running") throw std::logic_error("A capture is already running");
    }
    if (reader_.joinable()) reader_.join();
    if (device.empty() || device.size() > 256 || filter.size() > 1024 ||
        device.find('\0') != std::string::npos || filter.find('\0') != std::string::npos)
        throw std::invalid_argument("Invalid interface or filter length");
    int pipes[2];
    if (pipe2(pipes, O_CLOEXEC) != 0) throw std::runtime_error("Cannot create capture pipe");
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipes[0]);
    posix_spawn_file_actions_addclose(&actions, pipes[1]);
    char *args[] = {const_cast<char*>(helper_.c_str()), const_cast<char*>("--capture"),
                    const_cast<char*>(device.c_str()), const_cast<char*>(filter.c_str()), nullptr};
    pid_t pid;
    int spawn_error = posix_spawn(&pid, helper_.c_str(), &actions, nullptr, args, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipes[1]);
    if (spawn_error) { close(pipes[0]); throw std::runtime_error("Cannot launch capture helper: " + std::string(strerror(spawn_error))); }
    try {
        auto message = handshake(pipes[0]);
        if (message.type == ipc::Error) throw std::invalid_argument(std::string(message.payload.begin(), message.payload.end()));
        if (message.type != ipc::Ready || message.payload.size() != 4) throw std::runtime_error("Invalid capture handshake");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            datalink_ = int(ipc::get_u32(message.payload, 0));
            packets_.clear(); active_flows_.clear(); process_tracker_.reset();
            bytes_ = 0; received_ = 0; evicted_ = 0;
            stats_supported_ = false; stats_received_ = dropped_ = interface_dropped_ = 0;
            device_ = device; filter_ = requested_filter; effective_filter_ = filter; error_.clear(); ++session_;
            child_ = pid; state_ = "running";
            stop_requested_ = force_killed_ = false;
        }
        reader_ = std::thread(&Capture::receive, this, pipes[0], pid);
    } catch (...) {
        close(pipes[0]); kill(pid, SIGKILL);
        while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {}
        throw;
    }
}
void Capture::stop() {
    std::lock_guard<std::mutex> operation(operation_);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (child_ > 0) {
            stop_requested_ = true;
            kill(child_, SIGTERM);
            if (!finished_.wait_for(lock, std::chrono::milliseconds(750), [&] { return child_ <= 0; })) {
                force_killed_ = true;
                kill(child_, SIGKILL);
            }
        }
    }
    if (reader_.joinable()) reader_.join();
}
// 接收辅助进程的消息，再解析并保存数据包。
void Capture::receive(int fd, pid_t pid) {
    std::string failure;
    try {
        ipc::Message message;
        while (ipc::read_message(fd, message)) {
            if (message.type == ipc::Packet) {
                const auto& b = message.payload;
                if (b.size() < 16 || ipc::get_u32(b, 12) != b.size() - 16 ||
                    ipc::get_u32(b, 12) > 65535 || ipc::get_u32(b, 12) > ipc::get_u32(b, 8))
                    throw std::runtime_error("Invalid captured packet frame");
                std::vector<uint8_t> bytes(b.begin() + 16, b.end());
                add_packet(decode_packet(std::move(bytes), datalink_, int64_t(ipc::get_u64(b, 0)), ipc::get_u32(b, 8)));
            } else if (message.type == ipc::Stats) {
                if (message.payload.size() != 16) throw std::runtime_error("Invalid capture statistics frame");
                std::lock_guard<std::mutex> lock(mutex_);
                stats_received_ = ipc::get_u32(message.payload, 0);
                dropped_ = ipc::get_u32(message.payload, 4);
                interface_dropped_ = ipc::get_u32(message.payload, 8);
                stats_supported_ = ipc::get_u32(message.payload, 12) != 0;
            } else if (message.type == ipc::Error) {
                failure.assign(message.payload.begin(), message.payload.end());
            } else throw std::runtime_error("Unexpected capture message");
        }
    } catch (const std::exception& error) { failure = error.what(); kill(pid, SIGTERM); }
    close(fd);
    int result = 0;
    while (waitpid(pid, &result, 0) < 0 && errno == EINTR) {}
    std::lock_guard<std::mutex> lock(mutex_);
    child_ = -1;
    if (failure.empty() && WIFEXITED(result) && WEXITSTATUS(result) != 0)
        failure = "Capture helper exited with code " + std::to_string(WEXITSTATUS(result));
    if (failure.empty() && WIFSIGNALED(result) && WTERMSIG(result) != SIGTERM)
        failure = "Capture helper was terminated unexpectedly";
    if (failure.empty() && !stop_requested_) failure = "Capture helper stopped without a stop request";
    if (force_killed_) failure = "Capture helper exceeded the stop deadline and was forcibly terminated";
    error_ = failure;
    state_ = failure.empty() ? "stopped" : "error";
    finished_.notify_all();
}
std::size_t Capture::memory_cost(const Packet& p) {
    std::size_t cost = sizeof(Packet) + p.bytes.capacity() + p.fields.capacity() * sizeof(Field) + 512;
    for (const auto* s : {&p.source, &p.destination, &p.protocol, &p.summary, &p.network,
                          &p.transport, &p.tcp_flags, &p.http_line, &p.flow_id}) cost += s->capacity() + 32;
    for (const auto& f : p.fields) cost += f.section.capacity() + f.name.capacity() + f.value.capacity() + 96;
    cost += p.processes.capacity() * sizeof(ProcessOwner);
    for (const auto& owner : p.processes) cost += owner.name.capacity() + owner.start_ticks.capacity() + 64;
    return cost;
}
// 为 TCP 包归组会话，并限制保留的数据量。
void Capture::add_packet(Packet packet) {
    auto owners = packet.transport == "TCP" && !packet.fragmented && !packet.malformed
        ? process_tracker_.lookup(packet.source, packet.source_port, packet.destination, packet.destination_port)
        : std::vector<ProcessOwner>{};
    std::lock_guard<std::mutex> lock(mutex_);
    packet.id = next_id_++; ++received_;
    bool complete_tcp = std::any_of(packet.fields.begin(), packet.fields.end(),
        [](const Field& f) { return f.section == "TCP" && f.name == "sequence"; });
    if (complete_tcp && !packet.fragmented && !packet.malformed) {
        auto source = endpoint(packet.source, packet.source_port);
        auto destination = endpoint(packet.destination, packet.destination_port);
        bool direction_a = source <= destination;
        auto key = direction_a ? source + "|" + destination : destination + "|" + source;
        auto it = active_flows_.find(key);
        bool syn = (packet.tcp_flag_bits & 0x12) == 0x02;
        bool fresh = it == active_flows_.end();
        if (!fresh) {
            const Flow& f = it->second;
            fresh = packet.timestamp_us - f.last > 120000000 ||
                (syn && (f.reset || (f.fin_a && f.fin_b) || (!f.have_syn_a && !f.have_syn_b) ||
                    (direction_a ? f.have_syn_a && f.syn_sequence_a != packet.tcp_sequence
                                 : f.have_syn_b && f.syn_sequence_b != packet.tcp_sequence)));
        }
        if (fresh) {
            if (active_flows_.size() >= 4096 && it == active_flows_.end()) {
                auto oldest = std::min_element(active_flows_.begin(), active_flows_.end(),
                    [](const auto& a, const auto& b) { return a.second.last < b.second.last; });
                active_flows_.erase(oldest);
            }
            Flow f; f.id = "tcp-" + std::to_string(next_flow_++);
            active_flows_[key] = f;
        }
        Flow& f = active_flows_.at(key);
        bool new_owner = false;
        for (const auto& owner : owners) {
            bool known = false;
            for (const auto& saved : f.processes) if (saved.key() == owner.key()) known = true;
            if (!known && f.processes.size() < 32) { f.processes.push_back(owner); new_owner = true; }
        }
        packet.processes = f.processes;
        if (new_owner) for (auto& saved : packets_) if (saved.flow_id == f.id) {
            bytes_ -= memory_cost(saved); saved.processes = f.processes; bytes_ += memory_cost(saved);
        }
        if (syn) {
            (direction_a ? f.have_syn_a : f.have_syn_b) = true;
            (direction_a ? f.syn_sequence_a : f.syn_sequence_b) = packet.tcp_sequence;
        }
        if (packet.tcp_flag_bits & 0x01) (direction_a ? f.fin_a : f.fin_b) = true;
        if (packet.tcp_flag_bits & 0x04) f.reset = true;
        f.last = packet.timestamp_us;
        packet.flow_id = f.id;
    }
    bytes_ += memory_cost(packet);
    packets_.push_back(std::move(packet));
    while (!packets_.empty() && (packets_.size() > capacity_ || bytes_ > memory_limit_)) {
        bytes_ -= memory_cost(packets_.front()); packets_.pop_front(); ++evicted_;
    }
}
std::string Capture::status_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::ostringstream out;
    out << "{\"state\":" << json_string(state_) << ",\"error\":" << json_string(error_)
        << ",\"interface\":" << json_string(device_) << ",\"filter\":" << json_string(filter_)
        << ",\"effective_filter\":" << json_string(effective_filter_)
        << ",\"session\":" << session_ << ",\"received\":" << received_ << ",\"retained\":" << packets_.size()
        << ",\"evicted\":" << evicted_ << ",\"bytes\":" << bytes_
        << ",\"oldest_id\":" << (packets_.empty() ? next_id_ : packets_.front().id)
        << ",\"latest_id\":" << (next_id_ - 1) << ",\"stats\":{\"supported\":" << (stats_supported_ ? "true" : "false")
        << ",\"received\":" << stats_received_ << ",\"dropped\":" << dropped_
        << ",\"interface_dropped\":null,\"interface_dropped_supported\":false}}";
    return out.str();
}
std::string Capture::packet_summary(const Packet& p) {
    std::ostringstream out;
    bool ports_known = std::any_of(p.fields.begin(), p.fields.end(),
        [](const Field& f) { return (f.section == "TCP" || f.section == "UDP") && f.name == "source_port"; });
    out << "{\"id\":" << p.id << ",\"ports_known\":" << (ports_known ? "true" : "false")
        << ",\"timestamp_us\":" << p.timestamp_us << ",\"length\":" << p.wire_length
        << ",\"caplen\":" << p.bytes.size() << ",\"source\":" << json_string(p.source)
        << ",\"destination\":" << json_string(p.destination) << ",\"source_port\":" << p.source_port
        << ",\"destination_port\":" << p.destination_port << ",\"protocol\":" << json_string(p.protocol)
        << ",\"network\":" << json_string(p.network) << ",\"transport\":" << json_string(p.transport)
        << ",\"summary\":" << json_string(p.summary) << ",\"flow_id\":" << json_string(p.flow_id)
        << ",\"tcp_flags\":" << json_string(p.tcp_flags) << ",\"truncated\":" << (p.truncated ? "true" : "false")
        << ",\"malformed\":" << (p.malformed ? "true" : "false")
        << ",\"fragmented\":" << (p.fragmented ? "true" : "false") << ",\"processes\":[";
    bool first_owner = true;
    for (const auto& owner : p.processes) {
        if (!first_owner) out << ',';
        first_owner = false;
        out << "{\"key\":" << json_string(owner.key()) << ",\"pid\":" << owner.pid
            << ",\"uid\":" << owner.uid << ",\"name\":" << json_string(owner.name)
            << ",\"start_ticks\":" << json_string(owner.start_ticks) << '}';
    }
    out << "]}";
    return out.str();
}
namespace {
void validate_protocol(const std::string& protocol) {
    static const std::set<std::string> protocols{"ALL", "HTTP", "DNS", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6", "UNKNOWN"};
    if (!protocols.count(protocol)) throw std::invalid_argument("Unknown display protocol");
}
bool matches(const Packet& p, const std::string& protocol,
             const std::string& needle, const std::string& flow) {
    if (protocol != "ALL" && p.protocol != protocol && p.network != protocol && p.transport != protocol) return false;
    if (!flow.empty() && p.flow_id != flow) return false;
    if (needle.rfind("process:", 0) == 0) {
        for (const auto& owner : p.processes) if (owner.key() == needle.substr(8)) return true;
        return false;
    }
    return needle.empty() || lower(p.source + " " + p.destination + " " + p.summary + " " + p.protocol + " "
        + std::to_string(p.source_port) + " " + std::to_string(p.destination_port)).find(needle) != std::string::npos;
}
}
std::string Capture::packets_json(uint64_t after, const std::string& protocol,
                                 const std::string& search, const std::string& flow,
                                 std::optional<int64_t> from_us, std::optional<int64_t> to_us) const {
    validate_protocol(protocol);
    if ((from_us && *from_us <= 0) || (to_us && *to_us <= 0) ||
        (from_us && to_us && *from_us > *to_us)) throw std::invalid_argument("Invalid time interval");
    std::lock_guard<std::mutex> lock(mutex_);
    auto needle = lower(search);
    uint64_t cursor = after;
    std::size_t count = 0;
    std::string result = "{\"packets\":[";
    for (const auto& p : packets_) {
        if (p.id <= after) continue;
        cursor = p.id;
        if (!matches(p, protocol, needle, flow)) continue;
        if ((from_us && p.timestamp_us < *from_us) || (to_us && p.timestamp_us > *to_us)) continue;
        if (count++) result += ',';
        result += packet_summary(p);
        if (count == 250) break;
    }
    auto oldest = packets_.empty() ? next_id_ : packets_.front().id;
    return result + "],\"cursor\":" + std::to_string(cursor) + ",\"oldest_id\":" + std::to_string(oldest)
        + ",\"gap\":" + ((after && oldest > after && oldest - after > 1) ? "true" : "false") + '}';
}
std::string Capture::timeline_json(uint64_t after, const std::string& protocol,
                                  const std::string& search, const std::string& flow, std::size_t bins) const {
    validate_protocol(protocol);
    if (bins < 16 || bins > 200) throw std::invalid_argument("Bins must be 16..200");
    std::lock_guard<std::mutex> lock(mutex_);
    const auto needle = lower(search);
    std::vector<const Packet*> selected;
    int64_t start = 0, end = 0;
    uint64_t bytes = 0;
    for (const auto& p : packets_) {
        if (p.id <= after || !matches(p, protocol, needle, flow)) continue;
        if (selected.empty()) start = end = p.timestamp_us;
        else { start = std::min(start, p.timestamp_us); end = std::max(end, p.timestamp_us); }
        selected.push_back(&p);
        bytes += p.wire_length;
    }
    // 使用无符号减法处理跨越有符号零点的时间戳。
    uint64_t span = uint64_t(end) - uint64_t(start);
    if (!selected.empty() && span < 1000) {
        if (start > std::numeric_limits<int64_t>::max() - 1000)
            throw std::invalid_argument("Timeline timestamp cannot be padded");
        end = start + 1000;
        span = 1000;
    }
    std::ostringstream out;
    out << "{\"session\":" << session_ << ",\"oldest_id\":" << (packets_.empty() ? next_id_ : packets_.front().id)
        << ",\"latest_id\":" << next_id_ - 1 << ",\"matched\":" << selected.size() << ",\"bytes\":" << bytes
        << ",\"start_us\":" << start << ",\"end_us\":" << end << ",\"bins\":[";
    if (!selected.empty()) {
        // 计算 floor(span * i / bins)，避免乘法溢出。
        auto offset = [&](std::size_t i) { return span / bins * i + (span % bins) * i / bins; };
        std::vector<uint64_t> counts(bins), sizes(bins);
        for (const auto* p : selected) {
            const auto delta = uint64_t(p->timestamp_us) - uint64_t(start);
            std::size_t lo = 0, hi = bins;
            while (lo + 1 < hi) {
                auto mid = (lo + hi) / 2;
                if (offset(mid) <= delta) lo = mid; else hi = mid;
            }
            ++counts[lo]; sizes[lo] += p->wire_length;
        }
        for (std::size_t i = 0; i < bins; ++i) {
            if (i) out << ',';
            out << "{\"start_us\":" << int64_t(uint64_t(start) + offset(i))
                << ",\"end_us\":" << int64_t(uint64_t(start) + offset(i + 1))
                << ",\"packets\":" << counts[i] << ",\"bytes\":" << sizes[i] << '}';
        }
    }
    out << "]}";
    return out.str();
}
std::string Capture::packet_json(uint64_t id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(packets_.begin(), packets_.end(), [id](const Packet& p) { return p.id == id; });
    if (it == packets_.end()) return {};
    auto result = packet_summary(*it); result.pop_back();
    result += ",\"fields\":[";
    bool first = true;
    for (const auto& f : it->fields) {
        if (!first) result += ',';
        first = false;
        result += "{\"section\":" + json_string(f.section) + ",\"name\":" + json_string(f.name)
            + ",\"value\":" + json_string(f.value) + ",\"offset\":" + std::to_string(f.offset)
            + ",\"length\":" + std::to_string(f.length) + '}';
    }
    result += "],\"http_line\":" + json_string(it->http_line) + ",\"hex\":\"";
    static const char *digits = "0123456789abcdef";
    for (auto byte : it->bytes) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result + "\"}";
}
std::string Capture::flows_json() const {
    struct Summary { std::string a, b, state = "active"; uint64_t packets = 0, bytes = 0; int64_t start = 0, last = 0; bool fa = false, fb = false; std::vector<ProcessOwner> owners; };
    std::map<std::string, Summary> flows;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& p : packets_) {
        if (p.flow_id.empty()) continue;
        auto& f = flows[p.flow_id];
        auto s = endpoint(p.source, p.source_port), d = endpoint(p.destination, p.destination_port);
        if (!f.packets) { f.a = std::min(s, d); f.b = std::max(s, d); f.start = p.timestamp_us; }
        ++f.packets; f.bytes += p.wire_length; f.last = p.timestamp_us;
        if (p.processes.size() > f.owners.size()) f.owners = p.processes;
        if (p.tcp_flag_bits & 1) (s == f.a ? f.fa : f.fb) = true;
        if (p.tcp_flag_bits & 4) f.state = "reset";
        else if (f.state != "reset" && f.fa && f.fb) f.state = "closed";
        else if (f.state != "reset" && (f.fa || f.fb)) f.state = "closing";
    }
    std::string result = "{\"flows\":[";
    bool first = true;
    for (const auto& item : flows) {
        if (!first) result += ',';
        first = false;
        const auto& f = item.second;
        result += "{\"id\":" + json_string(item.first) + ",\"endpoint_a\":" + json_string(f.a)
            + ",\"endpoint_b\":" + json_string(f.b) + ",\"packets\":" + std::to_string(f.packets)
            + ",\"bytes\":" + std::to_string(f.bytes) + ",\"started_us\":" + std::to_string(f.start)
            + ",\"last_us\":" + std::to_string(f.last) + ",\"state\":" + json_string(f.state)
            + ",\"processes\":" + owners_json(f.owners) + '}';
    }
    return result + "]}";
}
// 使用仍保留的会话数据重组并配对 HTTP 请求与响应。
std::string Capture::http_exchanges_json(const std::string& flow) const {
    namespace http = http_stream;
    std::lock_guard<std::mutex> lock(mutex_);
    std::array<http::Direction, 2> directions;
    std::string client;
    for (const auto& p : packets_) {
        if (p.flow_id != flow || (p.tcp_flag_bits & 0x12) != 2) continue;
        const auto source = endpoint(p.source, p.source_port);
        if (!client.empty() && client != source) return "{\"state\":\"uncertain_direction\",\"exchanges\":[]}";
        client = source;
        directions[0].base = p.tcp_sequence + 1;
    }
    if (client.empty()) return "{\"state\":\"missing_handshake\",\"exchanges\":[]}";
    for (const auto& p : packets_) if (p.flow_id == flow && (p.tcp_flag_bits & 0x12) == 0x12 &&
        endpoint(p.source, p.source_port) != client && p.tcp_ack == *directions[0].base) {
        directions[1].base = p.tcp_sequence + 1;
        break;
    }
    if (!directions[1].base) return "{\"state\":\"missing_handshake\",\"exchanges\":[]}";
    for (const auto& p : packets_) if (p.flow_id == flow) {
        directions[endpoint(p.source, p.source_port) == client ? 0 : 1].append(p);
    }
    const auto request = directions[0].prefix(), response = directions[1].prefix();
    std::string result = "[";
    std::size_t a = 0, b = 0;
    unsigned count = 0;
    const char* issue = "incomplete_message";
    auto metadata = [](const http::Message& message) {
        return "{\"headers\":" + json_string(std::string(message.headers)) +
            ",\"body_bytes\":" + std::to_string(message.body_size) +
            ",\"framing\":" + json_string(message.framing) + '}';
    };
    for (; count < 64 && a < request.size(); ++count) {
        auto req = http::parse(request, a, false, issue);
        if (!req) break;
        if (req->method == "CONNECT") { issue = "unsupported_framing"; break; }
        auto next = b;
        auto res = http::parse(response, next, true, issue, req->method);
        while (res && res->status < 200 && res->status != 101) {
            next = res->end;
            res = http::parse(response, next, true, issue, req->method);
        }
        if (!res) break;
        if (res->status == 101) { issue = "unsupported_framing"; break; }
        if (count) result += ',';
        const auto* first = directions[0].source[a];
        const auto* reply = directions[1].source[next];
        const auto* last = directions[1].source[res->end - 1];
        auto completed = reply->timestamp_us;
        for (auto i = next; i < res->end; ++i) completed = std::max(completed, directions[1].source[i]->timestamp_us);
        result += "{\"request\":" + json_string(std::string(req->line)) + ",\"response\":" + json_string(std::string(res->line))
            + ",\"request_packet\":" + std::to_string(first->id) + ",\"response_packet\":" + std::to_string(reply->id);
        result += ",\"method\":" + json_string(std::string(req->method)) + ",\"target\":" + json_string(std::string(req->target))
            + ",\"status\":" + std::to_string(res->status) + ",\"request_details\":" + metadata(*req)
            + ",\"response_details\":" + metadata(*res) + ",\"response_last_packet\":" + std::to_string(last->id)
            + ",\"request_us\":" + std::to_string(first->timestamp_us) + ",\"response_us\":" + std::to_string(reply->timestamp_us)
            + ",\"response_complete_us\":" + std::to_string(completed);
        if (reply->timestamp_us >= first->timestamp_us) {
            result += ",\"elapsed_us\":" + std::to_string(uint64_t(reply->timestamp_us) - uint64_t(first->timestamp_us));
        }
        result += '}';
        a = req->end;
        b = res->end;
        issue = "incomplete_message";
    }
    const char* state = count ? "complete" : "no_messages";
    if (a < request.size() || b < response.size()) state = issue;
    if (count == 64 && (a < request.size() || b < response.size())) state = "analysis_limit";
    if (directions[0].limited || directions[1].limited) state = "analysis_limit";
    if (directions[0].truncated || directions[1].truncated) state = "truncated_capture";
    if ((!directions[0].conflict && request.size() < directions[0].bytes.size()) ||
        (!directions[1].conflict && response.size() < directions[1].bytes.size())) state = "missing_segments";
    if (directions[0].conflict || directions[1].conflict) state = "conflicting_overlap";
    return "{\"state\":" + json_string(state) +
        ",\"exchanges\":" + result + "]}";
}
std::string Capture::export_pcap() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string data;
    auto put = [&](uint32_t v, int n) { for (int i = 0; i < n; ++i) data += char((v >> (8 * i)) & 255); };
    put(0xa1b2c3d4, 4); put(2, 2); put(4, 2); put(0, 4); put(0, 4); put(65535, 4); put(uint32_t(datalink_), 4);
    for (const auto& p : packets_) {
        put(uint32_t(p.timestamp_us / 1000000), 4); put(uint32_t(p.timestamp_us % 1000000), 4);
        put(uint32_t(p.bytes.size()), 4); put(p.wire_length, 4);
        data.append(reinterpret_cast<const char*>(p.bytes.data()), p.bytes.size());
    }
    return data;
}
}
