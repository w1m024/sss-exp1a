#pragma once
#include "packet.hpp"
#include <deque>
#include <map>
#include <optional>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <sys/types.h>

namespace wirelens {
class Capture {
public:
    explicit Capture(std::string helper, std::size_t capacity = 5000,
                     std::size_t memory_limit = 64 * 1024 * 1024);
    ~Capture();
    void start(const std::string& device, const std::string& filter, const std::string& requested_filter);
    void stop();
    std::string status_json() const;
    std::string packets_json(uint64_t after, const std::string& protocol,
                             const std::string& search, const std::string& flow,
                             std::optional<int64_t> from_us = {}, std::optional<int64_t> to_us = {}) const;
    std::string timeline_json(uint64_t after, const std::string& protocol,
                              const std::string& search, const std::string& flow, std::size_t bins) const;
    std::string packet_json(uint64_t id) const;
    std::string flows_json() const;
    std::string export_pcap() const;
private:
    struct Flow {
        std::string id;
        int64_t last = 0;
        uint32_t syn_sequence_a = 0, syn_sequence_b = 0;
        bool have_syn_a = false, have_syn_b = false;
        bool fin_a = false, fin_b = false, reset = false;
        std::vector<ProcessOwner> processes;
    };
    void receive(int fd, pid_t pid);
    void add_packet(Packet packet);
    static std::string packet_summary(const Packet& packet);
    static std::size_t memory_cost(const Packet& packet);
    std::string helper_;
    std::size_t capacity_, memory_limit_;
    mutable std::mutex mutex_;
    std::mutex operation_;
    std::condition_variable finished_;
    std::thread reader_;
    pid_t child_ = -1;
    std::string state_ = "idle", error_, device_, filter_, effective_filter_;
    int datalink_ = 1;
    uint64_t next_id_ = 1, session_ = 0, received_ = 0, evicted_ = 0, next_flow_ = 1;
    std::size_t bytes_ = 0;
    bool stats_supported_ = false;
    bool stop_requested_ = false, force_killed_ = false;
    uint32_t stats_received_ = 0, dropped_ = 0, interface_dropped_ = 0;
    std::deque<Packet> packets_;
    std::map<std::string, Flow> active_flows_;
    ProcessTracker process_tracker_;
};
std::string interfaces_json();
}
