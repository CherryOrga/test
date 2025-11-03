#include "remote_function.h"

#include <algorithm>
#include <exception>
#include <utility>

#include "io.h"

namespace remote {

loader& loader::instance() {
    static loader instance;
    return instance;
}

std::future<std::vector<uint8_t>> loader::prepare(const std::string& name) {
    auto promise = std::make_shared<promise_t>();
    auto future = promise->get_future();

    std::lock_guard lock(m_mutex);
    auto it = m_pending.find(name);
    if (it != m_pending.end()) {
        try {
            it->second->set_exception(std::make_exception_ptr(std::runtime_error("duplicate request")));
        } catch (...) {
        }
        m_pending.erase(it);
    }

    m_pending.emplace(name, std::move(promise));
    return future;
}

void loader::fulfill(const std::string& name, std::vector<uint8_t>&& bytes) {
    std::shared_ptr<promise_t> promise;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_pending.find(name);
        if (it == m_pending.end()) {
            io::log("no pending request for remote function {}", name);
            return;
        }
        promise = std::move(it->second);
        m_pending.erase(it);
    }

    promise->set_value(std::move(bytes));
}

void loader::fail(const std::string& name, const std::string& reason) {
    std::shared_ptr<promise_t> promise;
    {
        std::lock_guard lock(m_mutex);
        auto it = m_pending.find(name);
        if (it == m_pending.end()) {
            return;
        }
        promise = std::move(it->second);
        m_pending.erase(it);
    }

    try {
        promise->set_exception(std::make_exception_ptr(std::runtime_error(reason)));
    } catch (...) {
    }
}

void loader::cancel(const std::string& name, const std::string& reason) {
    fail(name, reason);
}

patch_guard::patch_guard(stub_descriptor& stub, const std::vector<uint8_t>& bytes)
    : m_stub(stub), m_original(bytes.size()) {
    auto* address = reinterpret_cast<uint8_t*>(m_stub.address);
    std::copy(address, address + bytes.size(), m_original.begin());

    DWORD old_protect = 0;
    if (!VirtualProtect(address, bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        throw std::runtime_error("VirtualProtect failed while loading remote function");
    }

    std::copy(bytes.begin(), bytes.end(), address);
    FlushInstructionCache(GetCurrentProcess(), address, bytes.size());

    DWORD tmp = 0;
    VirtualProtect(address, bytes.size(), old_protect, &tmp);
}

patch_guard::~patch_guard() {
    auto* address = reinterpret_cast<uint8_t*>(m_stub.address);
    DWORD old_protect = 0;
    if (!VirtualProtect(address, m_original.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        io::log_error("failed to restore memory protection for remote function {} while unloading", m_stub.name);
        return;
    }

    std::copy(m_original.begin(), m_original.end(), address);
    FlushInstructionCache(GetCurrentProcess(), address, m_original.size());

    DWORD tmp = 0;
    VirtualProtect(address, m_original.size(), old_protect, &tmp);
}

}  // namespace remote

