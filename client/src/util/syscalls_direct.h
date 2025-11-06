#pragma once
#include <windows.h>
#include <winternl.h>

namespace syscall_direct {

// Direct syscall structures (inspired by SysWhispers3)
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

// Syscall number for NtDeviceIoControlFile (Windows 10 22H2: 0x07)
// Note: This changes per Windows version - should be dynamically resolved
constexpr DWORD SYSCALL_NtDeviceIoControlFile = 0x07;

// Direct syscall stub - bypasses usermode hooks
extern "C" NTSTATUS __stdcall NtDeviceIoControlFile_Direct(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
);

// Assembly stub (should be in .asm file, but simplified here)
// This would normally be:
// mov r10, rcx
// mov eax, SYSCALL_NtDeviceIoControlFile
// syscall
// ret

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

// Safe recv using direct syscalls to bypass hooks
inline int recv_safe(SOCKET s, char* buf, int len, int flags) {
    // Check if recv is hooked
    auto recv_ptr = reinterpret_cast<void*>(&recv);
    bool hooked = is_function_hooked(recv_ptr);

    if (!hooked) {
        // Use normal recv if not hooked
        return recv(s, buf, len, flags);
    }

    // If hooked, use direct syscall path
    // This would require implementing AFD_RECV via NtDeviceIoControlFile
    // For now, use a fresh copy of Ws2_32.dll loaded from System32

    HMODULE hCleanWs2 = LoadLibraryExA(
        "C:\\Windows\\System32\\ws2_32.dll",
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (!hCleanWs2) {
        return SOCKET_ERROR;
    }

    using recv_t = int (WINAPI*)(SOCKET, char*, int, int);
    auto clean_recv = reinterpret_cast<recv_t>(GetProcAddress(hCleanWs2, "recv"));

    if (!clean_recv) {
        FreeLibrary(hCleanWs2);
        return SOCKET_ERROR;
    }

    int result = clean_recv(s, buf, len, flags);
    FreeLibrary(hCleanWs2);

    return result;
}

// Safe send using direct syscalls
inline int send_safe(SOCKET s, const char* buf, int len, int flags) {
    auto send_ptr = reinterpret_cast<void*>(&send);
    bool hooked = is_function_hooked(send_ptr);

    if (!hooked) {
        return send(s, buf, len, flags);
    }

    // Load clean copy
    HMODULE hCleanWs2 = LoadLibraryExA(
        "C:\\Windows\\System32\\ws2_32.dll",
        NULL,
        DONT_RESOLVE_DLL_REFERENCES
    );

    if (!hCleanWs2) {
        return SOCKET_ERROR;
    }

    using send_t = int (WINAPI*)(SOCKET, const char*, int, int);
    auto clean_send = reinterpret_cast<send_t>(GetProcAddress(hCleanWs2, "send"));

    if (!clean_send) {
        FreeLibrary(hCleanWs2);
        return SOCKET_ERROR;
    }

    int result = clean_send(s, buf, len, flags);
    FreeLibrary(hCleanWs2);

    return result;
}

} // namespace syscall_direct
