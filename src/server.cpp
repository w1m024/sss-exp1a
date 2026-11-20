#include "capture.hpp"
#include "json.hpp"
#include <httplib.h>
#include <sys/random.h>
#include <unistd.h>
#include <signal.h>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <sstream>
#include <thread>
#include <atomic>
#include <limits>

namespace {
volatile sig_atomic_t quitting = 0;
void quit(int) { quitting = 1; }
std::string token() {
    unsigned char bytes[32];
    std::size_t offset = 0;
    while (offset < sizeof(bytes)) {
        ssize_t n = getrandom(bytes + offset, sizeof(bytes) - offset, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw std::runtime_error("Cannot obtain secure session randomness");
        offset += std::size_t(n);
    }
    std::ostringstream out;
    for (auto b : bytes) out << std::hex << std::setw(2) << std::setfill('0') << unsigned(b);
    return out.str();
}
bool same_token(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned difference = 0;
    for (std::size_t i = 0; i < a.size(); ++i) difference |= unsigned(a[i] ^ b[i]);
    return difference == 0;
}
uint64_t number(const std::string& text) {
    if (text.empty() || text.size() > 20) throw std::invalid_argument("Invalid numeric parameter");
    uint64_t n = 0;
    for (char c : text) {
        if (c < '0' || c > '9' || n > (std::numeric_limits<uint64_t>::max() - unsigned(c - '0')) / 10)
            throw std::invalid_argument("Invalid numeric parameter");
        n = n * 10 + unsigned(c - '0');
    }
    return n;
}
void failure(httplib::Response& response, int code, const std::string& error) {
    response.status = code;
    response.set_content("{\"error\":" + wirelens::json_string(error) + '}', "application/json; charset=utf-8");
}
}
int main(int argc, char **argv) {
    try {
        std::string helper = "/opt/wirelens/libexec/wirelens-capture";
        std::string web = WIRELENS_WEB_ROOT;
        int port = 8080;
        std::size_t capacity = 5000, memory_limit = 64 * 1024 * 1024;
        for (int i = 1; i < argc; ++i) {
            std::string option = argv[i];
            if (option == "--help") {
                std::cout << "wirelens [--port 8080] [--web-dir PATH] [--capture-helper PATH] [--capacity 5000] [--memory-mib 64]\n";
                return 0;
            }
            if (i + 1 >= argc) throw std::invalid_argument("Missing option value");
            std::string value = argv[++i];
            if (option == "--port") { auto n = number(value); if (n < 1024 || n > 65535) throw std::invalid_argument("Port must be 1024..65535"); port = int(n); }
            else if (option == "--capture-helper") helper = value;
            else if (option == "--web-dir") web = value;
            else if (option == "--capacity") { auto n = number(value); if (n < 1 || n > 10000) throw std::invalid_argument("Capacity must be 1..10000"); capacity = n; }
            else if (option == "--memory-mib") { auto n = number(value); if (n < 1 || n > 128) throw std::invalid_argument("Memory limit must be 1..128 MiB"); memory_limit = n * 1024 * 1024; }
            else throw std::invalid_argument("Unknown option: " + option);
        }
        if (getuid() == 0 || geteuid() == 0) throw std::runtime_error("Run the web service as an ordinary user; only install the capture helper with privileges");
        wirelens::Capture capture(helper, capacity, memory_limit);
        httplib::Server server;
        server.new_task_queue = [] { return new httplib::ThreadPool(4, 4, 64); };
        server.set_payload_max_length(4096);
        server.set_read_timeout(3, 0); server.set_write_timeout(3, 0);
        server.set_keep_alive_max_count(50);
        server.set_default_headers({
            {"Cache-Control", "no-store"}, {"X-Content-Type-Options", "nosniff"},
            {"X-Frame-Options", "DENY"}, {"Referrer-Policy", "no-referrer"},
            {"Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"}
        });
        const auto secret = token();
        std::set<std::string> hosts{"127.0.0.1:" + std::to_string(port), "localhost:" + std::to_string(port)};
        std::set<std::string> origins{"http://127.0.0.1:" + std::to_string(port), "http://localhost:" + std::to_string(port)};
        server.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
            if (!hosts.count(req.get_header_value("Host"))) {
                failure(res, 403, "Only the local service hostname is accepted"); return httplib::Server::HandlerResponse::Handled;
            }
            if (req.path.rfind("/api/", 0) == 0) {
                const auto origin = req.get_header_value("Origin");
                if ((!origin.empty() && !origins.count(origin)) || req.get_header_value("Sec-Fetch-Site") == "cross-site") {
                    failure(res, 403, "Cross-origin capture access is not allowed"); return httplib::Server::HandlerResponse::Handled;
                }
                if (req.path != "/api/session" && !same_token(secret, req.get_header_value("X-Capture-Token"))) {
                    failure(res, 401, "Missing or invalid capture session token"); return httplib::Server::HandlerResponse::Handled;
                }
            }
            return httplib::Server::HandlerResponse::Unhandled;
        });
        auto json_route = [](auto function) {
            return [function](const httplib::Request& req, httplib::Response& res) {
                try { res.set_content(function(req), "application/json; charset=utf-8"); }
                catch (const std::invalid_argument& error) { failure(res, 422, error.what()); }
                catch (const std::logic_error& error) { failure(res, 409, error.what()); }
                catch (const std::exception& error) { failure(res, 500, error.what()); }
            };
        };
        server.Get("/api/session", json_route([&](const auto&) { return "{\"version\":\"1.0\",\"token\":" + wirelens::json_string(secret) + '}'; }));
        server.Get("/api/interfaces", json_route([](const auto&) { return wirelens::interfaces_json(); }));
        server.Get("/api/status", json_route([&](const auto&) { return capture.status_json(); }));
        server.Post("/api/start", json_route([&](const auto& req) {
            if (!req.has_param("interface")) throw std::invalid_argument("Choose a capture interface");
            auto requested = req.get_param_value("filter");
            if (requested.size() > 950) throw std::invalid_argument("Capture filter must be at most 950 bytes");
            auto effective = requested.empty() ? "not tcp port " + std::to_string(port)
                : "(" + requested + ") and not tcp port " + std::to_string(port);
            capture.start(req.get_param_value("interface"), effective, requested);
            return capture.status_json();
        }));
        server.Post("/api/stop", json_route([&](const auto&) { capture.stop(); return capture.status_json(); }));
        server.Get("/api/packets", json_route([&](const auto& req) {
            auto search = req.get_param_value("search"), flow = req.get_param_value("flow");
            if (search.size() > 256 || flow.size() > 64) throw std::invalid_argument("Display filter too long");
            auto time_param = [&](const char* name) -> std::optional<int64_t> {
                if (!req.has_param(name)) return {};
                auto value = number(req.get_param_value(name));
                if (!value || value > uint64_t(std::numeric_limits<int64_t>::max()))
                    throw std::invalid_argument("Time must be a positive int64 microsecond value");
                return int64_t(value);
            };
            return capture.packets_json(req.has_param("after") ? number(req.get_param_value("after")) : 0,
                req.has_param("protocol") ? req.get_param_value("protocol") : "ALL", search, flow, time_param("from_us"), time_param("to_us"));
        }));
        server.Get("/api/timeline", json_route([&](const auto& req) {
            auto search = req.get_param_value("search"), flow = req.get_param_value("flow");
            if (search.size() > 256 || flow.size() > 64) throw std::invalid_argument("Display filter too long");
            auto bins = req.has_param("bins") ? number(req.get_param_value("bins")) : 80;
            if (bins < 16 || bins > 200) throw std::invalid_argument("Bins must be 16..200");
            return capture.timeline_json(req.has_param("after") ? number(req.get_param_value("after")) : 0,
                req.has_param("protocol") ? req.get_param_value("protocol") : "ALL", search, flow, std::size_t(bins));
        }));
        server.Get(R"(/api/packets/(\d+))", [&](const auto& req, auto& res) {
            try {
                auto packet = capture.packet_json(number(req.matches[1].str()));
                if (packet.empty()) failure(res, 404, "Packet is no longer retained");
                else res.set_content(packet, "application/json; charset=utf-8");
            } catch (const std::exception& error) { failure(res, 422, error.what()); }
        });
        server.Get("/api/flows", json_route([&](const auto&) { return capture.flows_json(); }));
        server.Get("/api/flows/http", json_route([&](const auto& req) {
            const auto flow = req.get_param_value("flow");
            if (flow.size() < 5 || flow.size() > 24 || flow.compare(0, 4, "tcp-") ||
                flow.find_first_not_of("0123456789", 4) != std::string::npos) throw std::invalid_argument("Invalid TCP flow");
            return capture.http_exchanges_json(flow);
        }));
        server.Get("/api/export", [&](const auto&, auto& res) {
            res.set_header("Content-Disposition", "attachment; filename=wirelens.pcap");
            res.set_content(capture.export_pcap(), "application/vnd.tcpdump.pcap");
        });
        std::vector<std::pair<std::string, std::string>> assets{{"/", "index.html"}, {"/app.css", "app.css"}, {"/app.js", "app.js"}, {"/timeline.js", "timeline.js"}, {"/vendor/split.js", "vendor/split.js"}, {"/vendor/echarts.min.js", "vendor/echarts.min.js"}};
        for (const auto& name : {"record-start", "record-stop", "filter", "download", "clear-list", "search", "right-panel-close"}) {
            auto file = std::string("vendor/devtools/") + name + ".svg";
            assets.emplace_back('/' + file, file);
        }
        for (const auto& entry : assets) {
            std::ifstream input(web + '/' + entry.second, std::ios::binary);
            if (!input) throw std::runtime_error("Missing web asset: " + entry.second);
            std::string content((std::istreambuf_iterator<char>(input)), {});
            auto type = entry.second == "index.html" ? "text/html; charset=utf-8" : entry.second == "app.css" ? "text/css; charset=utf-8" : entry.second.size() >= 4 && entry.second.substr(entry.second.size() - 4) == ".svg" ? "image/svg+xml" : "text/javascript; charset=utf-8";
            server.Get(entry.first, [content, type](const auto&, auto& res) { res.set_content(content, type); });
        }
        server.set_error_handler([](const auto&, auto& res) { if (res.body.empty()) failure(res, res.status, "Request not supported"); });
        if (!server.bind_to_port("127.0.0.1", port)) throw std::runtime_error("Cannot bind the local HTTP port");
        struct sigaction action{}; action.sa_handler = quit; sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, nullptr); sigaction(SIGTERM, &action, nullptr);
        std::atomic<bool> done{false};
        std::thread shutdown([&] {
            while (!done && !quitting) std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (quitting) server.stop();
        });
        std::cout << "WireLens ready at http://127.0.0.1:" << port << " (ordinary-user web service)" << std::endl;
        bool listened = server.listen_after_bind();
        done = true; shutdown.join(); capture.stop();
        return listened ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "WireLens: " << error.what() << '\n'; return 1;
    }
}
