#include "pdb_symbols.h"

#include <optional>
#include <stdexcept>

#ifdef _WIN32
#include <Windows.h>
#include <dia2.h>
#endif

#include <string>

namespace remote::tool {

#ifdef _WIN32

namespace {
constexpr auto kDiaDataSourceClsid = L"{E6756135-1E65-4D17-8576-610761398C3C}";
constexpr auto kDiaDataSourceIid = L"{79F1BB5F-B66E-48E5-B6A9-1545C323CA3D}";
constexpr auto kDiaSessionIid = L"{2F609EE1-D1C8-4E24-8288-4EFF1C1BCAE4}";
constexpr auto kDiaEnumSymbolsByAddrIid = L"{B388EB14-BE4D-421D-A8A1-6CF7AB057086}";

template <typename T>
class com_ptr {
public:
    com_ptr() = default;
    ~com_ptr() { reset(); }

    T* get() const noexcept { return m_ptr; }
    T** put() noexcept {
        reset();
        return &m_ptr;
    }

    T* operator->() const noexcept { return m_ptr; }

    void reset(T* value = nullptr) noexcept {
        if (m_ptr) {
            m_ptr->Release();
        }
        m_ptr = value;
    }

    T* detach() noexcept {
        T* tmp = m_ptr;
        m_ptr = nullptr;
        return tmp;
    }

private:
    T* m_ptr{nullptr};
};

GUID guid_from_string(const wchar_t* str) {
    GUID guid{};
    if (FAILED(CLSIDFromString(str, &guid))) {
        throw std::runtime_error("failed to convert GUID string");
    }
    return guid;
}

class com_initializer {
public:
    com_initializer() {
        m_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        m_should_uninit = SUCCEEDED(m_result) || m_result == RPC_E_CHANGED_MODE;
    }

    ~com_initializer() {
        if (m_should_uninit) {
            CoUninitialize();
        }
    }

    bool ok() const { return m_should_uninit; }

private:
    HRESULT m_result{E_FAIL};
    bool m_should_uninit{false};
};

struct pdb_symbols::impl {
    com_ptr<IDiaDataSource> data_source;
    com_ptr<IDiaSession> session;
    com_ptr<IDiaEnumSymbolsByAddr> enum_by_addr;

    bool load(const std::filesystem::path& pdb_path, std::uint64_t image_base) {
        GUID clsid = guid_from_string(kDiaDataSourceClsid);
        GUID iid_data_source = guid_from_string(kDiaDataSourceIid);

        if (FAILED(CoCreateInstance(clsid, nullptr, CLSCTX_INPROC_SERVER, iid_data_source,
                                    reinterpret_cast<void**>(data_source.put())))) {
            return false;
        }

        auto wide_path = pdb_path.wstring();
        if (FAILED(data_source->loadDataFromPdb(wide_path.c_str()))) {
            return false;
        }

        GUID iid_session = guid_from_string(kDiaSessionIid);
        if (FAILED(data_source->openSession(reinterpret_cast<IDiaSession**>(session.put())))) {
            return false;
        }

        session->put_loadAddress(image_base);

        GUID iid_enum = guid_from_string(kDiaEnumSymbolsByAddrIid);
        if (FAILED(session->getSymbolsByAddr(reinterpret_cast<IDiaEnumSymbolsByAddr**>(enum_by_addr.put())))) {
            return false;
        }

        return true;
    }

    std::optional<std::uint32_t> function_size(std::uint32_t rva) const {
        if (!enum_by_addr.get()) {
            return std::nullopt;
        }

        com_ptr<IDiaSymbol> symbol;
        if (FAILED(enum_by_addr->symbolByRVA(rva, reinterpret_cast<IDiaSymbol**>(symbol.put())))) {
            return std::nullopt;
        }

        LONG symbol_rva = 0;
        if (FAILED(symbol->get_relativeVirtualAddress(&symbol_rva))) {
            return std::nullopt;
        }

        if (static_cast<std::uint32_t>(symbol_rva) != rva) {
            // The requested RVA may point within the function body; try to fetch the
            // previous symbol and ensure we resolve to the function start.
            com_ptr<IDiaSymbol> previous;
            if (FAILED(enum_by_addr->symbolByRVA(rva ? rva - 1 : rva,
                                                reinterpret_cast<IDiaSymbol**>(previous.put())))) {
                return std::nullopt;
            }

            LONG previous_rva = 0;
            if (FAILED(previous->get_relativeVirtualAddress(&previous_rva))) {
                return std::nullopt;
            }

            if (static_cast<std::uint32_t>(previous_rva) != rva) {
                symbol.reset(previous.detach());
                symbol_rva = previous_rva;
            }
        }

        ULONGLONG length = 0;
        if (FAILED(symbol->get_length(&length)) || length == 0) {
            return std::nullopt;
        }

        return static_cast<std::uint32_t>(length);
    }
};

struct pdb_symbols::com_init {
    com_initializer initializer;
};

#endif  // _WIN32

pdb_symbols::pdb_symbols() {
#ifdef _WIN32
    m_com = new com_init();
    if (!m_com->initializer.ok()) {
        delete m_com;
        m_com = nullptr;
    }
#endif
}

pdb_symbols::~pdb_symbols() {
#ifdef _WIN32
    delete m_impl;
    delete m_com;
#endif
}

bool pdb_symbols::load(const std::filesystem::path& pdb_path, std::uint64_t image_base) {
#ifdef _WIN32
    if (!m_com) {
        return false;
    }

    auto* impl_instance = new impl();
    if (!impl_instance->load(pdb_path, image_base)) {
        delete impl_instance;
        return false;
    }

    delete m_impl;
    m_impl = impl_instance;
    return true;
#else
    (void)pdb_path;
    (void)image_base;
    return false;
#endif
}

std::optional<std::uint32_t> pdb_symbols::function_size(std::uint32_t rva) const {
#ifdef _WIN32
    if (!m_impl) {
        return std::nullopt;
    }

    return m_impl->function_size(rva);
#else
    (void)rva;
    return std::nullopt;
#endif
}

}  // namespace remote::tool
