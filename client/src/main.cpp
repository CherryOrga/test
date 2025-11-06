#include "include.h"
#include "util/io.h"
#include "util/util.h"
#include "util/syscalls.h"
#include "client/client.h"
#include "injection/process.h"
#include "injection/mapper.h"
#include "hwid/hwid.h"
#include "util/apiset.h"
#include "util/remote_function.h"
#include "security/security.h"
#include "ui/ui.h"

void add_handlers(tcp::client& client) {
	client.connect_event.add([&]() {
		io::log("connected.");
	});

	client.receive_event.add([&](tcp::packet_t packet) {
		if (!packet) return;
		auto message = packet();
		auto id = packet.id;

		if (id == tcp::packet_id::session) {
			client.session_id = packet.session_id;
			/*hwid::hwid_data_t data;
			if (!hwid::fetch(data)) {
				client.session_result = tcp::session_result::hwid_fail;

				std::this_thread::sleep_for(std::chrono::seconds(5));

				client.shutdown();
				return;
			}*/

			nlohmann::json hwid_data;
			hwid_data["uid"] = 0;

			nlohmann::json json;
			json["hwid"] = hwid_data.dump();
			json["ver"] = client.ver;
			

			int ret = client.write(tcp::packet_t(json.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::hwid));
			if (ret <= 0) {
				client.hwid_result = tcp::hwid_result::hwid_fail;

				std::this_thread::sleep_for(std::chrono::seconds(5));

				client.shutdown();
				return;
			}
		}

        if (id == tcp::packet_id::function_bytes) {
                if (!nlohmann::json::accept(message)) {
                        io::log_error("invalid json payload for remote function response");
                        return;
                }

                auto j = nlohmann::json::parse(message);
                if (!j.contains("name")) {
                        io::log_error("remote function response missing name field");
                        return;
                }

                auto name = j["name"].get<std::string>();

                if (j.contains("error")) {
                        remote::loader::instance().fail(name, j["error"].get<std::string>());
                        return;
                }

                size_t expected = j.value("size", static_cast<size_t>(0));

                std::vector<char> buffer;
                int read = client.read_stream(buffer);

                if (read <= 0 || static_cast<size_t>(read) != expected) {
                        remote::loader::instance().fail(name, "size_mismatch");
                        return;
                }

                std::vector<uint8_t> bytes(buffer.begin(), buffer.end());
                remote::loader::instance().fulfill(name, std::move(bytes));
                return;
        }

        if (id == tcp::packet_id::hwid_resp) {
                if (!nlohmann::json::accept(message)) {
                        io::log_error("invalid json for hwid_resp");
                        client.shutdown();
                        return;
                }

                auto j = nlohmann::json::parse(message);
                if (!j.contains("status") || !j["status"].is_number()) {
                        io::log_error("hwid_resp missing or invalid status field");
                        client.shutdown();
                        return;
                }

                client.hwid_result = j["status"];
		}

                if (id == tcp::packet_id::login_resp) {
                        if (!nlohmann::json::accept(message)) {
                                io::log_error("invalid json for login_resp");
                                client.shutdown();
                                return;
                        }

                        auto j = nlohmann::json::parse(message);

                        client.games.clear();

                        if (j.contains("games") && j["games"].is_object()) {
                                auto games = j["games"];
                                for (auto& [key, value] : games.items()) {
                                        // Validate all required fields
                                        if (!value.contains("version") || !value.contains("process") ||
                                            !value.contains("id") || !value.contains("x64")) {
                                                io::log_error("game entry missing required fields");
                                                continue;
                                        }

                                        if (!value["version"].is_number() || !value["process"].is_string() ||
                                            !value["id"].is_number() || !value["x64"].is_boolean()) {
                                                io::log_error("game entry has invalid field types");
                                                continue;
                                        }

                                        uint8_t version = value["version"];
                                        std::string process = value["process"];
                                        uint8_t id = value["id"];
                                        bool x64 = value["x64"];

                                        client.games.emplace_back(game_data_t{ x64, id, version, key, process });
                                }
                        }

                        io::log("authorized.");
                        client.state = tcp::client_state::logged_in;
                }

		if (id == tcp::packet_id::game_select) {
			if (!nlohmann::json::accept(message)) {
				io::log_error("invalid json for game_select");
				client.shutdown();
				return;
			}

			auto j = nlohmann::json::parse(message);
			if (!j.contains("pe") || !j.contains("size")) {
				io::log_error("game_select missing required fields");
				client.shutdown();
				return;
			}

			if (!j["pe"].is_array() || j["pe"].size() < 2 || !j["size"].is_number()) {
				io::log_error("game_select has invalid field types");
				client.shutdown();
				return;
			}

			client.mapper_data.image_size = j["pe"][0];
			client.mapper_data.entry = j["pe"][1];
			int imports_size = j["size"];

			// Validate sizes (max 1MB each)
			constexpr size_t max_image_size = 1 * 1024 * 1024;
			constexpr size_t max_imports_size = 1 * 1024 * 1024;
			if (client.mapper_data.image_size > max_image_size || imports_size > max_imports_size) {
				io::log_error("game_select sizes too large");
				client.shutdown();
				return;
			}

			int size = client.read_stream(client.mapper_data.imports);
			if (size == imports_size) {
				io::log("got imports");
				client.state = tcp::client_state::imports_ready;
			}
		}

		if (id == tcp::packet_id::image) {
			int size = client.read_stream(client.mapper_data.image);

			if (size == client.mapper_data.image_size) {
				io::log("got image");
				client.state = tcp::client_state::image_ready;
			}
		}

		if (id == tcp::packet_id::ban) {
			client.state = tcp::client_state::blacklisted;

			client.shutdown();

			return;
		}

		io::log("{}:{}->{} {}", packet.seq, packet.session_id, message, id);
	});
}

int WinMain(HINSTANCE inst, HINSTANCE prev_inst, LPSTR cmd_args, int show_cmd) {
#ifndef _REL
	AllocConsole();

	FILE* fp = nullptr;
	freopen_s(&fp, "CONOUT$", "w", stdout);
#endif

	g_syscalls.init();

	tcp::client client;

	client.start("127.0.0.1", 6666);

	if (!client) {
		MessageBoxA(0, "failed to connect to the the server..", "client", MB_OK);

		return 0;
	}

	add_handlers(client);

	auto hwnd = ui::create_window(inst, { 400, 300 });

	if (!ui::create_device(hwnd)) {
		MessageBoxA(0, "internal graphics error, please check your video drivers.", "client", MB_OK);

		return 0;
	}

	std::thread mon{ tcp::client::monitor, std::ref(client) };
	mon.detach();

	std::thread mapper_thread{ mmap::thread, std::ref(client) };
	mapper_thread.detach();

	std::thread sec_thread{ security::thread, std::ref(client) };
	sec_thread.detach();

	ShowWindow(hwnd, show_cmd);

	ImGui::CreateContext();

	ImGui::StyleColorsDark();

	ImGui::GetIO().IniFilename = nullptr;
	ImGui::GetStyle().WindowRounding = 0.f;

	ImGui_ImplWin32_Init(hwnd);
	ImGui_ImplDX9_Init(ui::device);

	int offset_x = 0;
	int offset_y = 0;

	MSG msg;
	std::memset(&msg, 0, sizeof(msg));

	bool stop = false;

	while (msg.message != WM_QUIT) {
		if (PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
			continue;
		}

		if (stop) {
			client.shutdown();

			std::this_thread::sleep_for(std::chrono::seconds(3));

			break;
		}

		ImGui_ImplDX9_NewFrame();
		ImGui_ImplWin32_NewFrame();
		ImGui::NewFrame();

		if (ImGui::IsMouseClicked(0)) {
			POINT point;
			RECT rect;

			GetCursorPos(&point);
			GetWindowRect(hwnd, &rect);

			offset_x = point.x - rect.left;
			offset_y = point.y - rect.top;
		}

		ImGui::SetNextWindowSize(ImVec2{ 400, 300 }, ImGuiCond_::ImGuiCond_Always);
		ImGui::SetNextWindowPos(ImVec2{ 0, 0 }, ImGuiCond_::ImGuiCond_Always);


		ImGui::Begin("##main", 0, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar | ImGuiWindowFlags_NoScrollbar);

		if (ImGui::BeginMenuBar()) {
			ImGui::Text("client");
			ImGui::EndMenuBar();
		}

		if (ImGui::IsMouseDragging(ImGuiMouseButton_::ImGuiMouseButton_Left)) {
			POINT point;
			GetCursorPos(&point);

			SetWindowPos(hwnd, nullptr, point.x - offset_x, point.y - offset_y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
		}

		if (client.state == tcp::client_state::blacklisted) {
			ImGui::Text("your computer has been blacklisted.");
		}

		if (client.state == tcp::client_state::connecting) {
			if (client.hwid_result == -1) {
				ImGui::Text("connecting...");
			}

			if (client.hwid_result == tcp::hwid_result::hwid_fail) {
				ImGui::Text("internal client error.");

				stop = true;
			}

			if (client.hwid_result == tcp::hwid_result::version_mismatch) {
				ImGui::Text("please update your client.");

				stop = true;
			}


			if (client.hwid_result == tcp::hwid_result::hwid_blacklisted) {
				ImGui::Text("your computer is blacklisted.");

				stop = true;
			}

			if (client.hwid_result == tcp::hwid_result::ok) {
				ImGui::Text("connected.");

				client.state = tcp::client_state::idle;
			}
		}

                if (client.state == tcp::client_state::idle) {
                        ImGui::Text("awaiting authorization...");

                        if (ImGui::Button("exit")) {
                                stop = true;
                        }
                }

                if (client.state == tcp::client_state::logged_in) {
                        ImGui::BeginChild("list", ImVec2(150, 0), true);
                        static int selected = 0;
                        if (selected >= client.games.size()) {
                                selected = 0;
                        }

                        for (int i = 0; i < client.games.size(); i++) {
                                auto& game = client.games[i];
                                if (ImGui::Selectable(game.name.c_str(), selected == i)) {
                                        selected = i;
                                }
                        }
                        ImGui::EndChild();

                        ImGui::SameLine();

                        ImGui::BeginGroup();
                        ImGui::BeginChild("data", ImVec2(0, -ImGui::GetFrameHeightWithSpacing()));
                        if (client.games.empty()) {
                                ImGui::Text("no games available.");
                        }
                        else {
                                auto game = client.games[selected];
                                ImGui::Text("%s", game.name.c_str());
                                ImGui::Separator();

                                ImGui::Text("version %d", game.version);

                                if (ImGui::Button("inject")) {
                                        client.selected_game = game;

                                        nlohmann::json j;
                                        j["id"] = client.selected_game.process_name;
                                        j["x64"] = client.selected_game.x64;

                                        int ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write,
                                                client.session_id,
                                                tcp::packet_id::game_select));

                                        if (ret <= 0) {
                                                ImGui::Text("Failed to send request, please try again.");
                                        }
                                }
                        }

                        ImGui::EndChild();
                        if (ImGui::Button("exit")) {
                                stop = true;
			}
			ImGui::EndGroup();
		}

		if (client.state == tcp::client_state::waiting) {
			ImGui::Text("waiting for the process...");
		}

		if (client.state == tcp::client_state::imports_ready) {
			ImGui::Text("please wait...");
		}

		if (client.state == tcp::client_state::image_ready) {
			ImGui::Text("please wait...");
		}


		if (client.state == tcp::client_state::injected) {
			ImGui::Text("done.");

			stop = true;
		}

		ImGui::End();

		ImGui::EndFrame();

		if (ui::device->BeginScene() == D3D_OK) {
			ImGui::Render();
			ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
			ui::device->EndScene();
		}

		HRESULT result = ui::device->Present(0, 0, 0, 0);

		if (result == D3DERR_DEVICELOST && ui::device->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
			ImGui_ImplDX9_InvalidateDeviceObjects();
			HRESULT hr = ui::device->Reset(&ui::present_params);
			if (hr == D3DERR_INVALIDCALL) {
				io::log_error("reset failed.");

				break;
			}
			ImGui_ImplDX9_CreateDeviceObjects();
		}
	}

	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	ui::cleanup_device();
	DestroyWindow(hwnd);
}
