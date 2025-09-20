#define NOMINMAX

#include <windows.h>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <set>
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>


using byte = unsigned char;


namespace logger {
    enum class Color : WORD {
        Default = 7,
        Gray = 8,
        Red = FOREGROUND_RED | FOREGROUND_INTENSITY,
        Green = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Blue = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Cyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Magenta = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        White = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE
    };

    static HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    static void set(Color c) {
        SetConsoleTextAttribute(hConsole, static_cast<WORD>(c));
    }

    static void prefix(const char* tag, Color c) {
        set(Color::Gray);
        std::cout << "[";
        set(c);
        std::cout << tag;
        set(Color::Gray);
        std::cout << "] ";
        set(Color::Default);
    }

    static void log(const std::string& s)    { prefix("+", Color::Green); std::cout << s << "\n"; }
    static void raw(const std::string& s)    {  std::cout << s << "\n"; }
    static void task(const std::string& s)   { prefix("*", Color::Cyan); std::cout << s << "\n"; }
    static void warn(const std::string& s)   { prefix("!", Color::Yellow); std::cout << s << "\n"; }
    static void err(const std::string& s)    { prefix("ERR", Color::Red); std::cout << s << "\n"; }
    static void dbg(const std::string& s)    { prefix("DBG", Color::Yellow); std::cout << s << "\n"; }
    static void title(const std::string& s)  { set(Color::Magenta); std::cout << s << "\n"; set(Color::Default); }
}

static bool safe_read(const std::vector<byte>& buf, size_t off, void* out, size_t len) {
    if (off + len > buf.size()) return false;
    memcpy(out, buf.data() + off, len);
    return true;
}

template<typename T>
T ptr_from_rva(const std::vector<byte>& buf, DWORD rva, PIMAGE_NT_HEADERS nt) {
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        DWORD va = sec->VirtualAddress;
        DWORD vs = sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData;
        if (rva >= va && rva < va + vs) {
            DWORD fileOffset = rva - va + sec->PointerToRawData;
            if (fileOffset + sizeof(void*) <= buf.size())
                return reinterpret_cast<T>(const_cast<byte*>(buf.data()) + fileOffset);
        }
    }
    return nullptr;
}

struct ExportInfo {
    std::string name;
    DWORD ordinal;
    DWORD funcRva;
};

struct ImportInfo {
    std::string dllName;
    size_t funcCount = 0;
};

int main(int argc, char** argv) {
    logger::title("=== DLL Proxy/Generator ===");
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <input_dll> <output_dir> [proxy_name]\n";
        return 1;
    }

    std::filesystem::path inPath = argv[1];
    std::filesystem::path outDir = argv[2];
    std::string proxyName = (argc >= 4) ? argv[3] : (inPath.stem().string());

    // read file
    std::ifstream ifs(inPath, std::ios::binary | std::ios::ate);
    if (!ifs) { logger::err("Failed to open input file"); return 1; }
    auto sz = ifs.tellg();
    ifs.seekg(0);
    std::vector<byte> buf((size_t)sz);
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), buf.size())) { logger::err("Failed to read file"); return 1; }

    logger::log("Successfully loaded DLL: " + inPath.string());

    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) { logger::err("Not a valid PE (too small)"); return 1; }
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buf.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { logger::err("Missing MZ signature"); return 1; }
    if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > buf.size()) { logger::err("Invalid e_lfanew"); return 1; }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(buf.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { logger::err("Invalid NT signature"); return 1; }
    {
        std::ostringstream ss;
        ss << std::hex << std::showbase;
        ss << "Entry Point: 0x" << nt->OptionalHeader.AddressOfEntryPoint;
        logger::log(ss.str());
    }
    {
        std::ostringstream ss;
        ss << std::hex << std::showbase;
        ss << "Image Base: 0x" << nt->OptionalHeader.ImageBase;
        logger::log(ss.str());
    }

    DWORD expRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    std::vector<ExportInfo> exports;
    if (expRva == 0) {
        logger::warn("No export table found");
    } else {
        auto expDir = ptr_from_rva<PIMAGE_EXPORT_DIRECTORY>(buf, expRva, nt);
        if (!expDir) {
            logger::err("Failed to map export directory");
        } else {
            DWORD* nameRvas = ptr_from_rva<DWORD*>(buf, expDir->AddressOfNames, nt);
            DWORD* funcRvas = ptr_from_rva<DWORD*>(buf, expDir->AddressOfFunctions, nt);
            WORD* ords = ptr_from_rva<WORD*>(buf, expDir->AddressOfNameOrdinals, nt);
            logger::raw("");
            if (!nameRvas || !funcRvas || !ords) {
                logger::warn("Export arrays missing or malformed");
            } else {
                logger::log("Found " + std::to_string(expDir->NumberOfNames) + " exported functions (named):");
                for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
                    char* name = ptr_from_rva<char*>(buf, nameRvas[i], nt);
                    if (!name) continue;
                    WORD ordIndex = ords[i];
                    DWORD funcRva = funcRvas[ordIndex];
                    ExportInfo ei;
                    ei.name = std::string(name);
                    ei.ordinal = ordIndex + expDir->Base;
                    ei.funcRva = funcRva;
                    exports.push_back(ei);
                    std::ostringstream ss;
                    ss << "  - " << ei.name << " (Ordinal: " << std::dec << ei.ordinal << ")";
                    logger::task(ss.str());
                }

                logger::raw(""); 

                // ordinal-only exports
                std::set<DWORD> seen;
                for (auto &e : exports) seen.insert(e.ordinal);

                for (DWORD o = 0; o < expDir->NumberOfFunctions; ++o) {
                    DWORD ord = o + expDir->Base;
                    if (seen.count(ord)) continue;
                    DWORD fRva = funcRvas[o];
                    char* maybe = ptr_from_rva<char*>(buf, fRva, nt);
                    if (maybe && strchr(maybe, '.')) {
                        // forwarded already; print info and skip
                        std::ostringstream ss;
                        ss << "  - Forwarded export at ordinal " << ord << " (already forwards to: " << maybe << ")";
                        logger::task(ss.str());
                        continue;
                    }
                    // ordinal-only
                    ExportInfo ei; ei.name = ""; ei.ordinal = ord; ei.funcRva = fRva;
                    exports.push_back(ei);
                    std::ostringstream ss;
                    ss << "  - (ordinal-only) @" << ord;
                    logger::task(ss.str());
                }

                logger::raw("");
            }
        }
    }

    // Imports summary
    DWORD impRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (impRva == 0) {
        logger::warn("No import table found");
    } else {
        auto 
        impDesc = ptr_from_rva<PIMAGE_IMPORT_DESCRIPTOR>(buf, impRva, nt);
        if (!impDesc) {
            logger::err("Failed to map import descriptors");
        } else {
            logger::log("Parsing import table:");
            for (; impDesc->Name; ++impDesc) {
                char* dllName = ptr_from_rva<char*>(buf, impDesc->Name, nt);
                if (!dllName) { ++impDesc; continue; }
                ImportInfo ii;
                ii.dllName = dllName;
                size_t fcount = 0;
                auto thunk = ptr_from_rva<PIMAGE_THUNK_DATA>(buf, impDesc->OriginalFirstThunk ? impDesc->OriginalFirstThunk : impDesc->FirstThunk, nt);
                if (thunk) {
                    for (; thunk->u1.AddressOfData; ++thunk) {
                        if (!(thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG)) {
                            auto ibn = ptr_from_rva<PIMAGE_IMPORT_BY_NAME>(buf, thunk->u1.AddressOfData, nt);
                            if (ibn) fcount++;
                        } else {
                            fcount++;
                        }
                    }
                }
                ii.funcCount = fcount;
                std::ostringstream ss;
                ss << "  - " << ii.dllName << " (" << ii.funcCount << " functions)";
                logger::task(ss.str());
            }
        }
    }

    logger::raw("");

    std::filesystem::create_directories(outDir);
    std::string realDllName = inPath.filename().string();

    // .def
    std::ofstream def(outDir / (proxyName + ".def"));
    def << "LIBRARY " << proxyName << "\nEXPORTS\n";
    for (const auto &e : exports) {
        if (!e.name.empty()) {
            def << "    " << e.name << " = " << realDllName << "." << e.name << "\n";
        } else {
            def << "    " << e.ordinal << " = " << realDllName << ".@" << e.ordinal << "\n";
        }
    }
    def.close();
    logger::log("Generated " + (outDir / (proxyName + ".def")).string());

    // proxy.cpp
    std::ofstream cpp(outDir / "main.cpp");
    cpp << R"(#include <windows.h>
#include <iostream>
#include <sstream>
#include <fstream>

static HMODULE real = NULL;
extern "C" IMAGE_DOS_HEADER __ImageBase;


std::string getTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buf);
}

void log_raw(const char* msg) {
    char path[MAX_PATH];
    GetModuleFileNameA((HMODULE)&__ImageBase, path, MAX_PATH);
    char* lastSlash = strrchr(path, '\\');
    if (lastSlash) *(lastSlash + 1) = '\0';
    strcat_s(path, MAX_PATH, ")" << proxyName << R"(.log");

    std::ofstream logFile(path, std::ios::app);
    if (logFile.is_open()) {
        logFile << msg << "\n";
        logFile.close();
    }

    std::cout << msg << std::endl;
}

void log(const char* msg) {
    std::ostringstream oss;
    oss << getTimestamp() << ": [ )" << realDllName << R"( ] " << msg;
    log_raw(oss.str().c_str());
}


int CreateConsole() {
    if (!AllocConsole()) {
        return 1;
    }

    // Redirect standard streams to console
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);
    freopen_s(&fDummy, "CONOUT$", "w", stderr);
    freopen_s(&fDummy, "CONIN$", "r", stdin);
    
    // Clear all stream states
    std::cout.clear();
    std::cerr.clear();
    std::cin.clear();

    return 0;
}

DWORD mainThread(LPVOID lpParameter){

    CreateConsole();
    log("Hello from proxy DLL!");
    std::cin.get();

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
    
        if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
            printf("DllMain: Failed to initialize COM library\n");
            return FALSE;
        }
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, mainThread, nullptr, 0, nullptr);

        if (!real) real = LoadLibraryA(")" << realDllName << R"(");
        break;
    case DLL_PROCESS_DETACH:
        if (real) { FreeLibrary(real); real = NULL; }
        break;
    }
    return TRUE;
}

)";
    cpp.close();
    logger::log("Generated " + (outDir / (proxyName + ".cpp")).string());

    // xmake.lua
    std::ofstream xmk(outDir / "xmake.lua");
    xmk << R"(
add_rules("mode.release")
set_languages("cxx23")

target(")" << proxyName << R"(")
    set_kind("shared")
    add_files("main.cpp")
    add_ldflags("/DEF:)" << proxyName << R"(.def")
    add_links("Ole32")
    set_optimize("fastest")
    set_targetdir(".")
)";
    xmk.close();
    logger::log("Generated " + (outDir / "xmake.lua").string());
    logger::log("Template generation complete!");

    logger::raw("\nBuild: cd " + outDir.string() + " && xmake");
    logger::raw("Run: xmake run " + proxyName + "\n");

    return 0;
}
