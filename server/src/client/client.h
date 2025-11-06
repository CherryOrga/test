#pragma once
#include "../server/packet.h"

namespace tcp {

enum client_state { idle = 0, logged_in, waiting, injected };

enum client_response {
  login_fail = 15494,
  hwid_mismatch = 11006,
  login_success = 61539,
  banned = 28618,
  server_error = 98679
};

enum hwid_result {
    blacklisted = 4567,
    version_mismatch = 5472,
    ok = 3247
  };

class client {
  int m_socket;

  std::time_t m_time;

  std::string m_ip;
  std::string m_session_id;

  int m_security_timeout_seconds;

 public:
  uint32_t hwid;
  std::string hwid_data;
  int state;

  std::time_t security_time;

  // Session-based random enum values
  std::unordered_map<std::string, int> enum_map;

  client() : m_socket{-1}, m_security_timeout_seconds{5} {};
  client(const int& socket, const std::string_view ip)
      : m_socket{std::move(socket)}, m_ip{ip}, state{-1} {
    // Random security timeout between 5 and 10 seconds
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(5, 10);
    m_security_timeout_seconds = dist(gen);

    // Generate random enum values for this session
    std::uniform_int_distribution<> enum_dist(10000, 99999);
    enum_map["hwid_result_ok"] = enum_dist(gen);
    enum_map["hwid_result_blacklisted"] = enum_dist(gen);
    enum_map["hwid_result_version_mismatch"] = enum_dist(gen);
    enum_map["login_success"] = enum_dist(gen);
    enum_map["login_fail"] = enum_dist(gen);

    // Generate random packet IDs
    std::uniform_int_distribution<> packet_dist(100, 255);
    enum_map["packet_session"] = packet_dist(gen);
    enum_map["packet_hwid"] = packet_dist(gen);
    enum_map["packet_hwid_resp"] = packet_dist(gen);
    enum_map["packet_login_resp"] = packet_dist(gen);
    enum_map["packet_game_select"] = packet_dist(gen);
    enum_map["packet_image"] = packet_dist(gen);
    enum_map["packet_ban"] = packet_dist(gen);
    enum_map["packet_security_report"] = packet_dist(gen);
    enum_map["packet_function_request"] = packet_dist(gen);
    enum_map["packet_function_bytes"] = packet_dist(gen);
  }
  ~client() = default;

  void cleanup() {
    close(m_socket);
    m_socket = -1;
  }

  void reset() {
   std::time(&m_time);
  }

  void reset_security_time() {
    std::time(&security_time);
  }

  bool timeout() { return std::difftime(std::time(nullptr), m_time) >= 300; }

  bool security_timeout() {
    return std::difftime(std::time(nullptr), security_time) >= m_security_timeout_seconds;
  }

  int write(const packet_t& packet) {
    if (!packet) return 0;
    return write(packet.message.data(), packet.message.size());
  }

  int write(const void* data, size_t size) {
    return send(m_socket, data, size, 0);
  }

  int read(void* data, size_t size) { return recv(m_socket, data, size, 0); }

  int stream(std::vector<char>& data, float* dur = nullptr);
  int read_stream(std::vector<char>& out);

  int stream(const std::string_view str) {
    std::vector<char> vec(str.begin(), str.end());
    return stream(vec);
  }

  int read_stream(std::string& str) {
    std::vector<char> out;
    int ret = read_stream(out);
    str.assign(out.begin(), out.end());
    return ret;
  }

  void gen_session();

  int& get_socket() { return m_socket; }
  auto& get_ip() { return m_ip; }

  operator bool() const { return m_socket > 0; }
  auto& operator()() { return m_session_id; }
};
};  // namespace tcp