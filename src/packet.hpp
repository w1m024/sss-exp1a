#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace wirelens {
struct Field {
    std::string section, name, value;
    std::size_t offset = 0, length = 0;
};
struct Packet {
    uint64_t id = 0;
    int64_t timestamp_us = 0;
    uint32_t wire_length = 0;
    int datalink = 0;
    std::vector<uint8_t> bytes;
    std::string source, destination, protocol = "UNKNOWN", summary;
    std::string network, transport, tcp_flags, http_line;
    uint16_t source_port = 0, destination_port = 0;
    uint32_t tcp_sequence = 0, tcp_ack = 0;
    uint8_t tcp_flag_bits = 0;
    bool truncated = false, malformed = false, fragmented = false;
    std::vector<Field> fields;
    std::string flow_id;
};
Packet decode_packet(std::vector<uint8_t> bytes, int datalink,
                     int64_t timestamp_us, uint32_t wire_length);
}
