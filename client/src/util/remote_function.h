#pragma once

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <windows.h>

#include <json.hpp>

#include "../client/client.h"
#include "../client/packet.h"

namespace remote {

struct stub_descriptor {
    const char* name;
    std::uintptr_t address;
};

#ifdef _MSC_VER
#pragma section(".remstub$m", read)
#define REMOTE_REGISTER_DESCRIPTOR(name)                                                     \
    __declspec(allocate(".remstub$m")) remote::stub_descriptor* remote_stub_ptr_##name =    \
        &remote_stub_##name;
#define REMOTE_CODE_ATTR __declspec(code_seg(".remote$text"))
#else
#define REMOTE_REGISTER_DESCRIPTOR(name)
#define REMOTE_CODE_ATTR
#endif

class loader {
public:
    static loader& instance();

    std::future<std::vector<uint8_t>> prepare(const std::string& name);
    void fulfill(const std::string& name, std::vector<uint8_t>&& bytes);
    void fail(const std::string& name, const std::string& reason);
    void cancel(const std::string& name, const std::string& reason);

private:
    using promise_t = std::promise<std::vector<uint8_t>>;

    std::mutex m_mutex;
    std::unordered_map<std::string, std::shared_ptr<promise_t>> m_pending;

    loader() = default;
};

class patch_guard {
public:
    patch_guard(stub_descriptor& stub, const std::vector<uint8_t>& bytes);
    ~patch_guard();

    patch_guard(const patch_guard&) = delete;
    patch_guard& operator=(const patch_guard&) = delete;

private:
    stub_descriptor& m_stub;
    std::vector<uint8_t> m_original;
};

constexpr auto default_timeout = std::chrono::seconds(5);

template <typename FnPtr, typename... Args>
auto invoke(tcp::client& client, stub_descriptor& stub, Args&&... args)
    -> typename std::invoke_result_t<FnPtr, Args...> {
    auto& mgr = loader::instance();
    auto future = mgr.prepare(stub.name);

    if (client.session_id.empty()) {
        mgr.cancel(stub.name, "no_session");
        throw std::runtime_error("client is not authenticated with the server");
    }

    nlohmann::json req;
    req["name"] = stub.name;

    const auto result = client.write(tcp::packet_t(req.dump(), tcp::packet_type::write,
        client.session_id, tcp::packet_id::function_request));

    if (result <= 0) {
        mgr.cancel(stub.name, "send_failed");
        throw std::runtime_error("failed to send remote function request");
    }

    if (future.wait_for(default_timeout) != std::future_status::ready) {
        mgr.cancel(stub.name, "timeout");
        throw std::runtime_error("timed out waiting for remote function bytes");
    }

    auto bytes = future.get();
    if (bytes.empty()) {
        throw std::runtime_error("received empty remote function payload");
    }

    patch_guard guard(stub, bytes);
    using fn_type = FnPtr;
    auto fn = reinterpret_cast<fn_type>(stub.address);

    if constexpr (std::is_void_v<std::invoke_result_t<fn_type, Args...>>) {
        fn(std::forward<Args>(args)...);
        return;
    } else {
        return fn(std::forward<Args>(args)...);
    }
}

}  // namespace remote

#define REMOTE_FUNCTION(ret, name, ...)                                                      \
    REMOTE_CODE_ATTR ret name(__VA_ARGS__);                                                  \
    namespace {                                                                              \
    remote::stub_descriptor remote_stub_##name{#name, reinterpret_cast<std::uintptr_t>(&name)}; \
    REMOTE_REGISTER_DESCRIPTOR(name)                                                         \
    }                                                                                        \
    REMOTE_CODE_ATTR ret name(__VA_ARGS__)

#define REMOTE_CALL(client, name, ...) \
    remote::invoke<decltype(&name)>(client, remote_stub_##name, __VA_ARGS__)

