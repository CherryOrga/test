#pragma once

#include "../util/io.h"
#include "../util/events.h"
#include "packet.h"

struct mapper_data_t {
	size_t image_size = 0;
	uint32_t entry = 0;
	std::string imports;
	std::vector<char> image;
};

struct game_data_t {
	bool x64;
	uint8_t id;
	uint8_t version;
	std::string name;
	std::string process_name;
};

namespace tcp {
	enum client_state {
		connecting = 0, idle, logging_in, logged_in, imports_ready, waiting, image_ready, injected, blacklisted
	};

	enum login_result {
		login_fail = 15494,
		hwid_mismatch = 11006,
		login_success = 61539,
		banned = 28618,
		server_error = 98679
	};

	enum hwid_result {
		hwid_fail = 5671,
		hwid_blacklisted = 4567,
		version_mismatch = 5472,
		ok = 3247
	};

	class client {
		int m_socket;
		std::atomic<bool> m_active;

	public:
		int state;
		int login_result;
		int hwid_result;
		mapper_data_t mapper_data;
		std::vector<game_data_t> games;
		game_data_t selected_game;

		std::string session_id;
		event<packet_t> receive_event;
		event<> connect_event;

		uint16_t ver = 4672;

		client() : m_socket{ -1 }, m_active{ false }, state{ client_state::connecting }, login_result{ -1 }, hwid_result{ -1 } {}

		void start(const std::string_view server_ip, const uint16_t port);

		__forceinline int write(const packet_t& packet) {
			if (!packet) return 0;
			return write(packet.message.data(), packet.message.size());
		}

		__forceinline int write(const void* data, int size) {
			return send(m_socket, data, size, 0);
		}

		__forceinline int read(void* data, int size) {
			return recv(m_socket, data, size, 0);
		}

		int read_stream(std::vector<char>& out);
		int stream(std::vector<char>& data);

		__forceinline int stream(const std::string_view str) {
			std::vector<char> vec(str.begin(), str.end());
			return stream(vec);
		}

		__forceinline int read_stream(std::string& str) {
			std::vector<char> out;
			int ret = read_stream(out);
			str.assign(out.begin(), out.end());
			return ret;
		}

		__forceinline int get_socket() { return m_socket; }

		operator bool() { return m_active.load(); }

		__forceinline void shutdown() {
			m_active.store(false);

			if (m_socket > 0) {
				closesocket(m_socket);
				m_socket = -1;
			}
		}

		static void monitor(client& client) {
			std::array<char, message_len> buf;
			while (client) {
				int ret = client.read(&buf[0], buf.size());
				if (ret <= 0) {
					if (!client) {
						break;
					}

					io::log_error("connection lost.");
					client.shutdown();
					break;
				}
				std::string msg(buf.data(), ret);

				client.receive_event.call(packet_t{msg, packet_type::read});
			}
		}
	};
}  // namespace tcp

