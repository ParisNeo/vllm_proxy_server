#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/thread.hpp>
#include <boost/tokenizer.hpp>
#include <boost/regex.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <sstream>

namespace http = boost::beast::http;
using tcp = boost::asio::ip::tcp;

std::map<std::string, std::pair<std::string, std::queue<int>>> servers;
std::map<std::string, std::string> authorized_users;
std::mutex mtx;

void add_access_log_entry(const std::string& log_path, const std::string& event, const std::string& user, const std::string& ip_address, const std::string& access, const std::string& server, int nb_queued_requests_on_server, const std::string& error) {
    std::stringstream ss;
    ss << std::chrono::system_clock::now() << ",";
    ss << event << ",";
    ss << user << ",";
    ss << ip_address << ",";
    ss << access << ",";
    ss << server << ",";
    ss << nb_queued_requests_on_server << ",";
    ss << error;

    std::ofstream log_file(log_path, std::ios_base::app);
    if (log_file.is_open()) {
        log_file << ss.str() << std::endl;
        log_file.close();
    }
}

void get_config(const std::string& filename) {
    boost::property_tree::ptree pt;
    boost::property_tree::ini_parser::read_ini(filename, pt);

    for (const auto& section : pt) {
        std::string name = section.first;
        servers[name] = std::make_pair(pt.get<std::string>(name + ".url"), std::queue<int>());
    }
}

void get_authorized_users(const std::string& filename) {
    std::ifstream users_file(filename);
    std::string line;

    while (std::getline(users_file, line)) {
        if (line.empty()) {
            continue;
        }
        size_t pos = line.find(':');
        std::string user = line.substr(0, pos);
        std::string key = line.substr(pos + 1);

        authorized_users[user] = key;
    }
}

void handle_request(const std::string& local_address, const std::string& config_filename, const std::string& users_filename, const std::string& log_path, int port, bool deactivate_security, boost::asio::io_context& io_context, http::request<http::string_body>& original_req, http::response<http::string_body>& response) {
    get_config(config_filename);
    get_authorized_users(users_filename);

    try {
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), port));

        while (true) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);

            boost::asio::streambuf request_buf;
            boost::asio::read_until(socket, request_buf, "\r\n\r\n");

            std::istream request_stream(&request_buf);
            http::request<http::string_body> req;
            req.parse(request_stream);

            std::string ip_address = socket.remote_endpoint().address().to_string();
            std::string user = "unknown";

            if (!deactivate_security) {
                mtx.lock();

                // Validate user and key
                std::string auth_header = req.base()[http::field::authorization];
                if (!auth_header.empty() && auth_header.substr(0, 7) == "Bearer ") {
                    std::string token = auth_header.substr(7);
                    boost::tokenizer<boost::char_separator<char>> tokenizer(token, boost::char_separator<char>(":"));
                    std::string t_user = tokenizer.begin();
                    std::string t_key = tokenizer.next();

                    if (authorized_users.count(t_user) && authorized_users[t_user] == t_key) {
                        user = t_user;
                    }
                }

                if (user == "unknown") {
                    add_access_log_entry(log_path, "rejected", user, ip_address, "Denied", "", -1, "Authentication failed");
                    http::response<http::string_body> res(http::status::unauthorized, req.version());
                    res.set(http::field::server, "Vllm Proxy Server");
                    res.set(http::field::content_type, "text/plain");
                    res.body() = "User is not authorized";
                    res.prepare_payload();

                    http::write(socket, res);
                    mtx.unlock();
                    continue;
                }

                // Find the server with the lowest number of queue entries.
                std::pair<std::string, std::pair<std::string, std::queue<int>>> min_queued_server = *std::min_element(servers.begin(), servers.end(), [](const auto& a, const auto& b) {
                    return a.second.second.size() < b.second.second.size();
                });

                // Apply the queuing mechanism only for a specific endpoint.
                std::queue<int>& que = min_queued_server.second.second;

                add_access_log_entry(log_path, "gen_request", user, ip_address, "Authorized", min_queued_server.first, que.size());
                que.push(1);

                mtx.unlock();

                // Process the request and send the response.
                std::string path = req.target().to_string();
                std::string method = req.method().to_string();

                original_req.target() = path;
                original_req.method() = method;
                original_req.set(http::field::host, min_queued_server.second.first);
                original_req.set(http::field::user_agent, req.at(http::field::user_agent));
                original_req.set(http::field::accept, req.at(http::field::accept));
                original_req.set(http::field::authorization, auth_header);

                for (const auto& header : req.base()) {
                    if (header.name_ == http::field::content_length || header.name_ == http::field::transfer_encoding) {
                        continue;
                    }
                    original_req.set(header.name_, header.value());
                }

                if (req.body().size() > 0) {
                    original_req.body() = req.body();
                    original_req.prepare_payload();
                }

                http::response<http::string_body> res;
                {
                    boost::beast::http::stream<tcp::socket> http_stream(io_context);
                    http_stream.connect(min_queued_server.second.first);
                    http_stream.write(original_req);
                    http_stream.read(res);
                }

                response = res;
                response.set(http::field::server, "Vllm Proxy Server");

                http::write(socket, response);

                mtx.lock();
                que.pop();
                add_access_log_entry(log_path, "gen_done", user, ip_address, "Authorized", min_queued_server.first, que.size());
                mtx.unlock();
            }
        }
    } catch (std::exception const& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    int port = 8000;
    std::string config_filename = "config.ini";
    std::string users_filename = "authorized_users.txt";
    std::string log_path = "access_log.txt";
    bool deactivate_security = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            std::cout << "Usage: vllm_proxy_server [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  --config=<filename>      Path to the config file (default: config.ini)" << std::endl;
            std::cout << "  --log_path=<filename>    Path to the access log file (default: access_log.txt)" << std::endl;
            std::cout << "  --users_list=<filename>  Path to the users list file (default: authorized_users.txt)" << std::endl;
            std::cout << "  --port=<port>            Port number for the server (default: 8000)" << std::endl;
            std::cout << "  -d, --deactivate_security Deactivate security" << std::endl;
            return 0;
        } else if (arg == "--config") {
            if (++i < argc) {
                config_filename = argv[i];
            } else {
                std::cerr << "Error: --config option requires a filename argument." << std::endl;
                return 1;
            }
        } else if (arg == "--log_path") {
            if (++i < argc) {
                log_path = argv[i];
            } else {
                std::cerr << "Error: --log_path option requires a filename argument." << std::endl;
                return 1;
            }
        } else if (arg == "--users_list") {
            if (++i < argc) {
                users_filename = argv[i];
            } else {
                std::cerr << "Error: --users_list option requires a filename argument." << std::endl;
                return 1;
            }
        } else if (arg == "--port") {
            if (++i < argc) {
                port = std::stoi(argv[i]);
            } else {
                std::cerr << "Error: --port option requires a port number argument." << std::endl;
                return 1;
            }
        } else if (arg == "-d" || arg == "--deactivate_security") {
            deactivate_security = true;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
    }

    boost::asio::io_context io_context;
    http::request<http::string_body> original_req;
    http::response<http::string_body> response;

    boost::thread t(handle_request, local_address, config_filename, users_filename, log_path, port, deactivate_security, std::ref(io_context), std::ref(original_req), std::ref(response));
    t.detach();

    io_context.run();

    return 0;
}
