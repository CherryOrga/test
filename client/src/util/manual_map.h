#pragma once
#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <vector>
#include <string>

namespace manual_map {

struct MappedDLL {
    uint8_t* base;
    size_t size;
    bool valid;

    MappedDLL() : base(nullptr), size(0), valid(false) {}
    ~MappedDLL() {
        if (base && valid) {
            VirtualFree(base, 0, MEM_RELEASE);
        }
    }
};

// Get function from manually mapped DLL
inline void* get_export(uint8_t* base, const char* func_name) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    auto exports_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exports_dir->Size == 0) return nullptr;

    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + exports_dir->VirtualAddress);
    auto names = reinterpret_cast<DWORD*>(base + exports->AddressOfNames);
    auto funcs = reinterpret_cast<DWORD*>(base + exports->AddressOfFunctions);
    auto ords = reinterpret_cast<WORD*>(base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (strcmp(name, func_name) == 0) {
            return base + funcs[ords[i]];
        }
    }

    return nullptr;
}

// Resolve imports for manually mapped DLL
inline bool resolve_imports(uint8_t* base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    auto import_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir->Size == 0) return true;

    auto import_desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + import_dir->VirtualAddress);

    while (import_desc->Name) {
        const char* dll_name = reinterpret_cast<const char*>(base + import_desc->Name);
        HMODULE dll = LoadLibraryA(dll_name);
        if (!dll) return false;

        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->OriginalFirstThunk);
        auto func_ptr = reinterpret_cast<PIMAGE_THUNK_DATA>(base + import_desc->FirstThunk);

        while (thunk->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                // Import by ordinal
                auto ordinal = IMAGE_ORDINAL(thunk->u1.Ordinal);
                func_ptr->u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress(dll, MAKEINTRESOURCEA(ordinal)));
            } else {
                // Import by name
                auto import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(base + thunk->u1.AddressOfData);
                func_ptr->u1.Function = reinterpret_cast<ULONGLONG>(GetProcAddress(dll, import_name->Name));
            }

            if (!func_ptr->u1.Function) return false;

            ++thunk;
            ++func_ptr;
        }

        ++import_desc;
    }

    return true;
}

// Apply relocations for manually mapped DLL
inline bool apply_relocations(uint8_t* base, uint8_t* preferred_base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);

    LONGLONG delta = base - preferred_base;
    if (delta == 0) return true; // No relocation needed

    auto reloc_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir->Size == 0) return true;

    auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(base + reloc_dir->VirtualAddress);

    while (reloc->VirtualAddress) {
        auto entries = reinterpret_cast<WORD*>(reinterpret_cast<uint8_t*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
        auto count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

        for (size_t i = 0; i < count; ++i) {
            WORD entry = entries[i];
            WORD type = entry >> 12;
            WORD offset = entry & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                auto ptr = reinterpret_cast<ULONGLONG*>(base + reloc->VirtualAddress + offset);
                *ptr += delta;
            } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                auto ptr = reinterpret_cast<DWORD*>(base + reloc->VirtualAddress + offset);
                *ptr += static_cast<DWORD>(delta);
            }
        }

        reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
            reinterpret_cast<uint8_t*>(reloc) + reloc->SizeOfBlock);
    }

    return true;
}

// Set memory protections for sections
inline bool set_section_permissions(uint8_t* base) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
    auto section = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD characteristics = section[i].Characteristics;
        DWORD protect = PAGE_NOACCESS;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protect = PAGE_EXECUTE_READWRITE;
            } else if (characteristics & IMAGE_SCN_MEM_READ) {
                protect = PAGE_EXECUTE_READ;
            } else {
                protect = PAGE_EXECUTE;
            }
        } else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        } else if (characteristics & IMAGE_SCN_MEM_READ) {
            protect = PAGE_READONLY;
        }

        if (protect != PAGE_NOACCESS) {
            DWORD old_protect;
            VirtualProtect(
                base + section[i].VirtualAddress,
                section[i].Misc.VirtualSize,
                protect,
                &old_protect
            );
        }
    }

    return true;
}

// Manual map a DLL from disk
inline MappedDLL map_dll_from_disk(const char* dll_path) {
    MappedDLL result;

    // Read DLL from disk
    HANDLE hFile = CreateFileA(dll_path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return result;

    DWORD file_size = GetFileSize(hFile, nullptr);
    std::vector<uint8_t> file_data(file_size);
    DWORD bytes_read;
    ReadFile(hFile, file_data.data(), file_size, &bytes_read, nullptr);
    CloseHandle(hFile);

    if (bytes_read != file_size) return result;

    // Parse PE headers
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(file_data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(file_data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    // Allocate memory for DLL
    size_t image_size = nt->OptionalHeader.SizeOfImage;
    uint8_t* base = static_cast<uint8_t*>(VirtualAlloc(
        nullptr,
        image_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    ));

    if (!base) return result;

    // Copy headers
    memcpy(base, file_data.data(), nt->OptionalHeader.SizeOfHeaders);

    // Copy sections
    auto section = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (section[i].SizeOfRawData > 0) {
            memcpy(
                base + section[i].VirtualAddress,
                file_data.data() + section[i].PointerToRawData,
                section[i].SizeOfRawData
            );
        }
    }

    // Apply relocations
    auto preferred_base = reinterpret_cast<uint8_t*>(nt->OptionalHeader.ImageBase);
    if (!apply_relocations(base, preferred_base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return result;
    }

    // Resolve imports
    if (!resolve_imports(base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        return result;
    }

    // Set section permissions
    set_section_permissions(base);

    result.base = base;
    result.size = image_size;
    result.valid = true;

    return result;
}

// Helper to get function from ws2_32.dll via manual mapping
template<typename FuncType>
inline FuncType get_ws2_function(const char* func_name) {
    static MappedDLL ws2_mapped;

    // Map ws2_32.dll only once (singleton pattern)
    if (!ws2_mapped.valid) {
        ws2_mapped = map_dll_from_disk("C:\\Windows\\System32\\ws2_32.dll");
        if (!ws2_mapped.valid) {
            return nullptr;
        }
    }

    return reinterpret_cast<FuncType>(get_export(ws2_mapped.base, func_name));
}

} // namespace manual_map
