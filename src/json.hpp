#pragma once
#include <string>
#include <sstream>
#include <iomanip>
namespace wirelens {
inline std::string json_string(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        if (c == '"') out << "\\\"";
        else if (c == '\\') out << "\\\\";
        else if (c == '\n') out << "\\n";
        else if (c == '\r') out << "\\r";
        else if (c == '\t') out << "\\t";
        else if (c < 32 || c >= 127) {
            out << "\\u00" << std::hex << std::setw(2) << std::setfill('0') << int(c) << std::dec;
        } else out << char(c);
    }
    return out.str() + '"';
}
}
