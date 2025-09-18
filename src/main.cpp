#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <algorithm>

struct ExportInfo {
    std::string name;
    DWORD ordinal;
    DWORD rva;
};

struct ImportInfo {
    std::string dllName;
    std::vector<std::string> functions;
};

class ReflectiveDLLGenerator {
private:
    std::vector<BYTE> dllData;
    std::vector<ExportInfo> exports;
    std::vector<ImportInfo> imports;
    std::string dllName;
    std::string className;
    
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_OPTIONAL_HEADER optionalHeader;
    
public:
    bool LoadDLL(const std::string& filePath) {
        std::ifstream file(filePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            std::cout << "[-] Failed to open file: " << filePath << std::endl;
            return false;
        }
        
        size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);
        
        dllData.resize(fileSize);
        file.read(reinterpret_cast<char*>(dllData.data()), fileSize);
        file.close();
        
        // Extract filename for class naming
        size_t lastSlash = filePath.find_last_of("\\/");
        size_t lastDot = filePath.find_last_of(".");
        dllName = filePath.substr(lastSlash + 1, lastDot - lastSlash - 1);
        className = "Reflective" + dllName + "Loader";
        
        return ParsePE();
    }
    
private:
    bool ParsePE() {
        if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
            std::cout << "[-] Invalid PE file - too small" << std::endl;
            return false;
        }
        
        dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData.data());
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cout << "[-] Invalid DOS signature" << std::endl;
            return false;
        }
        
        if (dosHeader->e_lfanew >= dllData.size()) {
            std::cout << "[-] Invalid NT headers offset" << std::endl;
            return false;
        }
        
        ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllData.data() + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cout << "[-] Invalid NT signature" << std::endl;
            return false;
        }
        
        optionalHeader = &ntHeaders->OptionalHeader;
        
        std::cout << "[+] Successfully parsed PE headers" << std::endl;
        std::cout << "[+] Entry Point: 0x" << std::hex << optionalHeader->AddressOfEntryPoint << std::endl;
        std::cout << "[+] Image Base: 0x" << std::hex << optionalHeader->ImageBase << std::endl;
        
        ParseExports();
        ParseImports();
        
        return true;
    }
    
    void ParseExports() {
        DWORD exportRva = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (exportRva == 0) {
            std::cout << "[!] No export table found" << std::endl;
            return;
        }
        
        PIMAGE_EXPORT_DIRECTORY exportDir = RvaToPointer<PIMAGE_EXPORT_DIRECTORY>(exportRva);
        if (!exportDir) return;
        
        DWORD* nameRvas = RvaToPointer<DWORD*>(exportDir->AddressOfNames);
        DWORD* functionRvas = RvaToPointer<DWORD*>(exportDir->AddressOfFunctions);
        WORD* ordinals = RvaToPointer<WORD*>(exportDir->AddressOfNameOrdinals);
        
        if (!nameRvas || !functionRvas || !ordinals) return;
        
        std::cout << "[+] Found " << exportDir->NumberOfNames << " exported functions:" << std::endl;
        
        for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
            char* name = RvaToPointer<char*>(nameRvas[i]);
            if (name) {
                ExportInfo info;
                info.name = std::string(name);
                info.ordinal = ordinals[i] + exportDir->Base;
                info.rva = functionRvas[ordinals[i]];
                exports.push_back(info);
                
                std::cout << "  - " << info.name << " (Ordinal: " << info.ordinal << ")" << std::endl;
            }
        }
    }
    
    void ParseImports() {
        DWORD importRva = optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (importRva == 0) {
            std::cout << "[!] No import table found" << std::endl;
            return;
        }
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = RvaToPointer<PIMAGE_IMPORT_DESCRIPTOR>(importRva);
        if (!importDesc) return;
        
        std::cout << "[+] Parsing import table:" << std::endl;
        
        while (importDesc->Name != 0) {
            char* dllNamePtr = RvaToPointer<char*>(importDesc->Name);
            if (!dllNamePtr) {
                importDesc++;
                continue;
            }
            
            ImportInfo importInfo;
            importInfo.dllName = std::string(dllNamePtr);
            
            PIMAGE_THUNK_DATA thunk = RvaToPointer<PIMAGE_THUNK_DATA>(importDesc->OriginalFirstThunk);
            if (!thunk) {
                thunk = RvaToPointer<PIMAGE_THUNK_DATA>(importDesc->FirstThunk);
            }
            
            if (thunk) {
                while (thunk->u1.AddressOfData != 0) {
                    if (!(thunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = RvaToPointer<PIMAGE_IMPORT_BY_NAME>(thunk->u1.AddressOfData);
                        if (importByName) {
                            importInfo.functions.push_back(std::string(reinterpret_cast<char*>(importByName->Name)));
                        }
                    }
                    thunk++;
                }
            }
            
            if (!importInfo.functions.empty()) {
                imports.push_back(importInfo);
                std::cout << "  - " << importInfo.dllName << " (" << importInfo.functions.size() << " functions)" << std::endl;
            }
            
            importDesc++;
        }
    }
    
    template<typename T>
    T RvaToPointer(DWORD rva) {
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (rva >= section->VirtualAddress && 
                rva < section->VirtualAddress + section->Misc.VirtualSize) {
                DWORD offset = rva - section->VirtualAddress + section->PointerToRawData;
                if (offset < dllData.size()) {
                    return reinterpret_cast<T>(dllData.data() + offset);
                }
            }
            section++;
        }
        return nullptr;
    }
    
public:
    void GenerateReflectiveLoader(const std::string& outputPath) {
        std::string headerPath = outputPath + "/" + className + ".h";
        std::string sourcePath = outputPath + "/" + className + ".cpp";
        
        GenerateHeader(headerPath);
        GenerateSource(sourcePath);
        GenerateExample(outputPath + "/example_usage.cpp");
        
        std::cout << "[+] Generated reflective loader template:" << std::endl;
        std::cout << "    Header: " << headerPath << std::endl;
        std::cout << "    Source: " << sourcePath << std::endl;
        std::cout << "    Example: " << outputPath << "/example_usage.cpp" << std::endl;
    }
    
private:
    void GenerateHeader(const std::string& path) {
        std::ofstream header(path);
        
        header << "#pragma once\n";
        header << "#include <windows.h>\n";
        header << "#include <vector>\n";
        header << "#include <string>\n\n";
        
        header << "class " << className << " {\n";
        header << "private:\n";
        header << "    static HMODULE hModule;\n";
        header << "    static std::vector<BYTE> dllData;\n";
        header << "    static bool isLoaded;\n\n";
        
        header << "    // Function pointers for exported functions\n";
        for (const auto& exp : exports) {
            header << "    static FARPROC " << exp.name << "Ptr;\n";
        }
        header << "\n";
        
        header << "    // Helper functions\n";
        header << "    static HMODULE LoadFromMemory(const BYTE* dllData, size_t size);\n";
        header << "    static void FixImports(PIMAGE_NT_HEADERS ntHeaders, BYTE* baseAddress);\n";
        header << "    static void FixRelocations(PIMAGE_NT_HEADERS ntHeaders, BYTE* baseAddress, DWORD_PTR delta);\n";
        header << "    static DWORD_PTR GetProcAddressFromModule(HMODULE hModule, const char* funcName);\n\n";
        
        header << "public:\n";
        header << "    // Load DLL from embedded resource or file\n";
        header << "    static bool LoadDLL(const std::vector<BYTE>& data);\n";
        header << "    static bool LoadDLL(const std::string& filePath);\n";
        header << "    static void UnloadDLL();\n";
        header << "    static bool IsLoaded() { return isLoaded; }\n\n";
        
        header << "    // Exported function wrappers\n";
        for (const auto& exp : exports) {
            header << "    template<typename... Args>\n";
            header << "    static auto Call" << exp.name << "(Args&&... args) {\n";
            header << "        if (" << exp.name << "Ptr) {\n";
            header << "            return reinterpret_cast<decltype(&" << exp.name << ")>(" << exp.name << "Ptr)(std::forward<Args>(args)...);\n";
            header << "        }\n";
            header << "        return decltype(" << exp.name << "(std::forward<Args>(args)...)){};\n";
            header << "    }\n\n";
        }
        
        header << "};\n";
        header.close();
    }
    
    void GenerateSource(const std::string& path) {
        std::ofstream source(path);
        
        source << "#include \"" << className << ".h\"\n";
        source << "#include <fstream>\n";
        source << "#include <iostream>\n\n";
        
        // Static member definitions
        source << "HMODULE " << className << "::hModule = nullptr;\n";
        source << "std::vector<BYTE> " << className << "::dllData;\n";
        source << "bool " << className << "::isLoaded = false;\n\n";
        
        for (const auto& exp : exports) {
            source << "FARPROC " << className << "::" << exp.name << "Ptr = nullptr;\n";
        }
        source << "\n";
        
        // LoadDLL implementations
        source << "bool " << className << "::LoadDLL(const std::vector<BYTE>& data) {\n";
        source << "    if (isLoaded) {\n";
        source << "        std::cout << \"[!] DLL already loaded\" << std::endl;\n";
        source << "        return true;\n";
        source << "    }\n\n";
        
        source << "    dllData = data;\n";
        source << "    hModule = LoadFromMemory(dllData.data(), dllData.size());\n\n";
        
        source << "    if (!hModule) {\n";
        source << "        std::cout << \"[-] Failed to load DLL from memory\" << std::endl;\n";
        source << "        return false;\n";
        source << "    }\n\n";
        
        source << "    // Get function pointers\n";
        for (const auto& exp : exports) {
            source << "    " << exp.name << "Ptr = GetProcAddress(hModule, \"" << exp.name << "\");\n";
        }
        source << "\n";
        
        source << "    isLoaded = true;\n";
        source << "    std::cout << \"[+] Successfully loaded DLL reflectively\" << std::endl;\n";
        source << "    return true;\n";
        source << "}\n\n";
        
        source << "bool " << className << "::LoadDLL(const std::string& filePath) {\n";
        source << "    std::ifstream file(filePath, std::ios::binary | std::ios::ate);\n";
        source << "    if (!file.is_open()) {\n";
        source << "        std::cout << \"[-] Failed to open file: \" << filePath << std::endl;\n";
        source << "        return false;\n";
        source << "    }\n\n";
        
        source << "    size_t fileSize = file.tellg();\n";
        source << "    file.seekg(0, std::ios::beg);\n\n";
        
        source << "    std::vector<BYTE> data(fileSize);\n";
        source << "    file.read(reinterpret_cast<char*>(data.data()), fileSize);\n";
        source << "    file.close();\n\n";
        
        source << "    return LoadDLL(data);\n";
        source << "}\n\n";
        
        source << "void " << className << "::UnloadDLL() {\n";
        source << "    if (hModule) {\n";
        source << "        FreeLibrary(hModule);\n";
        source << "        hModule = nullptr;\n";
        source << "    }\n";
        source << "    isLoaded = false;\n";
        for (const auto& exp : exports) {
            source << "    " << exp.name << "Ptr = nullptr;\n";
        }
        source << "    dllData.clear();\n";
        source << "}\n\n";
        
        // Reflective loading implementation
        source << "HMODULE " << className << "::LoadFromMemory(const BYTE* dllData, size_t size) {\n";
        source << "    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllData;\n";
        source << "    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;\n\n";
        
        source << "    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllData + dosHeader->e_lfanew);\n";
        source << "    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return nullptr;\n\n";
        
        source << "    // Allocate memory for the DLL\n";
        source << "    BYTE* baseAddress = (BYTE*)VirtualAlloc(nullptr, ntHeaders->OptionalHeader.SizeOfImage,\n";
        source << "                                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n";
        source << "    if (!baseAddress) return nullptr;\n\n";
        
        source << "    // Copy headers\n";
        source << "    memcpy(baseAddress, dllData, ntHeaders->OptionalHeader.SizeOfHeaders);\n\n";
        
        source << "    // Copy sections\n";
        source << "    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);\n";
        source << "    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {\n";
        source << "        if (section->SizeOfRawData > 0) {\n";
        source << "            memcpy(baseAddress + section->VirtualAddress,\n";
        source << "                   dllData + section->PointerToRawData,\n";
        source << "                   section->SizeOfRawData);\n";
        source << "        }\n";
        source << "        section++;\n";
        source << "    }\n\n";
        
        source << "    // Update NT headers pointer to new location\n";
        source << "    ntHeaders = (PIMAGE_NT_HEADERS)(baseAddress + dosHeader->e_lfanew);\n\n";
        
        source << "    // Fix imports\n";
        source << "    FixImports(ntHeaders, baseAddress);\n\n";
        
        source << "    // Fix relocations\n";
        source << "    DWORD_PTR delta = (DWORD_PTR)baseAddress - ntHeaders->OptionalHeader.ImageBase;\n";
        source << "    if (delta != 0) {\n";
        source << "        FixRelocations(ntHeaders, baseAddress, delta);\n";
        source << "    }\n\n";
        
        source << "    // Call DLL entry point\n";
        source << "    typedef BOOL(WINAPI* DllEntryPoint)(HINSTANCE, DWORD, LPVOID);\n";
        source << "    DllEntryPoint entryPoint = (DllEntryPoint)(baseAddress + ntHeaders->OptionalHeader.AddressOfEntryPoint);\n";
        source << "    if (entryPoint) {\n";
        source << "        entryPoint((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, nullptr);\n";
        source << "    }\n\n";
        
        source << "    return (HMODULE)baseAddress;\n";
        source << "}\n\n";
        
        // Helper function implementations
        source << "void " << className << "::FixImports(PIMAGE_NT_HEADERS ntHeaders, BYTE* baseAddress) {\n";
        source << "    DWORD importRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;\n";
        source << "    if (importRva == 0) return;\n\n";
        
        source << "    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importRva);\n\n";
        
        source << "    while (importDesc->Name != 0) {\n";
        source << "        char* dllName = (char*)(baseAddress + importDesc->Name);\n";
        source << "        HMODULE hDll = LoadLibraryA(dllName);\n\n";
        
        source << "        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(baseAddress + importDesc->FirstThunk);\n";
        source << "        PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)(baseAddress + importDesc->OriginalFirstThunk);\n\n";
        
        source << "        while (thunk->u1.AddressOfData != 0) {\n";
        source << "            if (origThunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG) {\n";
        source << "                thunk->u1.Function = GetProcAddressFromModule(hDll,\n";
        source << "                    (char*)(origThunk->u1.AddressOfData & 0xFFFF));\n";
        source << "            } else {\n";
        source << "                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + origThunk->u1.AddressOfData);\n";
        source << "                thunk->u1.Function = GetProcAddressFromModule(hDll, (char*)importByName->Name);\n";
        source << "            }\n";
        source << "            thunk++;\n";
        source << "            origThunk++;\n";
        source << "        }\n";
        source << "        importDesc++;\n";
        source << "    }\n";
        source << "}\n\n";
        
        source << "void " << className << "::FixRelocations(PIMAGE_NT_HEADERS ntHeaders, BYTE* baseAddress, DWORD_PTR delta) {\n";
        source << "    DWORD relocRva = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;\n";
        source << "    if (relocRva == 0) return;\n\n";
        
        source << "    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(baseAddress + relocRva);\n\n";
        
        source << "    while (reloc->VirtualAddress != 0) {\n";
        source << "        WORD* relocInfo = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));\n";
        source << "        int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);\n\n";
        
        source << "        for (int i = 0; i < numEntries; i++) {\n";
        source << "            int type = relocInfo[i] >> 12;\n";
        source << "            int offset = relocInfo[i] & 0xFFF;\n\n";
        
        source << "            if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {\n";
        source << "                DWORD_PTR* patchAddr = (DWORD_PTR*)(baseAddress + reloc->VirtualAddress + offset);\n";
        source << "                *patchAddr += delta;\n";
        source << "            }\n";
        source << "        }\n";
        source << "        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);\n";
        source << "    }\n";
        source << "}\n\n";
        
        source << "DWORD_PTR " << className << "::GetProcAddressFromModule(HMODULE hModule, const char* funcName) {\n";
        source << "    return (DWORD_PTR)GetProcAddress(hModule, funcName);\n";
        source << "}\n";
        
        source.close();
    }
    
    void GenerateExample(const std::string& path) {
        std::ofstream example(path);
        
        example << "#include \"" << className << ".h\"\n";
        example << "#include <iostream>\n\n";
        
        example << "int main() {\n";
        example << "    std::cout << \"Reflective " << dllName << " Loader Example\" << std::endl;\n\n";
        
        example << "    // Load DLL from file\n";
        example << "    if (!" << className << "::LoadDLL(\"path/to/" << dllName << ".dll\")) {\n";
        example << "        std::cout << \"[-] Failed to load DLL\" << std::endl;\n";
        example << "        return 1;\n";
        example << "    }\n\n";
        
        example << "    std::cout << \"[+] DLL loaded successfully!\" << std::endl;\n\n";
        
        if (!exports.empty()) {
            example << "    // Example: Call exported functions\n";
            example << "    try {\n";
            for (size_t i = 0; i < std::min((size_t)3, exports.size()); i++) {
                example << "        // auto result = " << className << "::Call" << exports[i].name << "(/* parameters */);\n";
            }
            example << "    } catch (const std::exception& e) {\n";
            example << "        std::cout << \"[-] Exception: \" << e.what() << std::endl;\n";
            example << "    }\n\n";
        }
        
        example << "    // Keep DLL loaded for demonstration\n";
        example << "    std::cout << \"Press Enter to unload DLL...\";\n";
        example << "    std::cin.get();\n\n";
        
        example << "    // Cleanup\n";
        example << "    " << className << "::UnloadDLL();\n";
        example << "    std::cout << \"[+] DLL unloaded\" << std::endl;\n\n";
        
        example << "    return 0;\n";
        example << "}\n";
        
        example.close();
    }
    
public:
    void GenerateXMakeFile(const std::string& outputPath) {
        std::ofstream xmake(outputPath + "/xmake.lua");
        
        xmake << "-- XMake build configuration for " << className << "\n";
        xmake << "set_project(\"" << className << "\")\n";
        xmake << "set_version(\"1.0.0\")\n";
        xmake << "set_xmakever(\"2.7.1\")\n\n";
        
        xmake << "-- Set C++ standard\n";
        xmake << "set_languages(\"cxx17\")\n\n";
        
        xmake << "-- Set build modes\n";
        xmake << "add_rules(\"mode.debug\", \"mode.release\")\n\n";
        
        xmake << "-- Windows specific settings\n";
        xmake << "if is_os(\"windows\") then\n";
        xmake << "    add_defines(\"WIN32\", \"_WINDOWS\")\n";
        xmake << "    add_syslinks(\"kernel32\", \"user32\")\n";
        xmake << "    add_cxxflags(\"/EHsc\")\n";
        xmake << "end\n\n";
        
        xmake << "-- DLL Analyzer executable\n";
        xmake << "target(\"dll_analyzer\")\n";
        xmake << "    set_kind(\"binary\")\n";
        xmake << "    add_files(\"main.cpp\")\n";
        xmake << "    set_targetdir(\"bin\")\n\n";
        
        xmake << "-- Reflective loader static library\n";
        xmake << "target(\"" << dllName << "_loader\")\n";
        xmake << "    set_kind(\"static\")\n";
        xmake << "    add_files(\"" << className << ".cpp\")\n";
        xmake << "    add_headerfiles(\"" << className << ".h\")\n";
        xmake << "    set_targetdir(\"lib\")\n\n";
        
        xmake << "-- Example usage executable\n";
        xmake << "target(\"example\")\n";
        xmake << "    set_kind(\"binary\")\n";
        xmake << "    add_files(\"example_usage.cpp\")\n";
        xmake << "    add_deps(\"" << dllName << "_loader\")\n";
        xmake << "    set_targetdir(\"bin\")\n\n";
        
        xmake << "-- Package configuration\n";
        xmake << "includes(\"@builtin/xpack\")\n";
        xmake << "xpack(\"" << dllName << "_reflective_loader\")\n";
        xmake << "    set_formats(\"zip\", \"tar.gz\")\n";
        xmake << "    set_basename(\"" << className << "-$(os)-$(arch)\")\n";
        xmake << "    add_targets(\"dll_analyzer\", \"" << dllName << "_loader\", \"example\")\n";
        xmake << "    add_files(\"README.md\")\n";
        
        xmake.close();
        std::cout << "[+] Generated xmake.lua" << std::endl;
    }
};

int main(int argc, char* argv[]) {
    std::cout << "=== Reflective DLL Loader Generator ===" << std::endl;
    std::cout << "Analyzes DLL files and generates automated reflective loader templates\n" << std::endl;
    
    if (argc != 3) {
        std::cout << "Usage: " << argv[0] << " <input_dll_path> <output_directory>" << std::endl;
        std::cout << "Example: " << argv[0] << " C:\\Windows\\System32\\kernel32.dll ./output" << std::endl;
        return 1;
    }
    
    std::string inputPath = argv[1];
    std::string outputPath = argv[2];
    
    // Create output directory
    CreateDirectoryA(outputPath.c_str(), nullptr);
    
    ReflectiveDLLGenerator generator;
    
    std::cout << "[+] Analyzing DLL: " << inputPath << std::endl;
    if (!generator.LoadDLL(inputPath)) {
        std::cout << "[-] Failed to analyze DLL" << std::endl;
        return 1;
    }
    
    std::cout << "\n[+] Generating reflective loader template..." << std::endl;
    generator.GenerateReflectiveLoader(outputPath);
    generator.GenerateXMakeFile(outputPath);
    
    std::cout << "\n[+] Template generation complete!" << std::endl;
    std::cout << "[+] Build instructions:" << std::endl;
    std::cout << "    1. cd " << outputPath << std::endl;
    std::cout << "    2. mkdir build && cd build" << std::endl;
    std::cout << "    3. cmake .." << std::endl;
    std::cout << "    4. cmake --build ." << std::endl;
    
    return 0;
}