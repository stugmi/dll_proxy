-- XMake build configuration for Reflective DLL Generator
set_project("ReflectiveDLLGenerator")
set_version("1.0.0")
set_xmakever("2.7.1")

-- Set C++ standard
set_languages("cxx17")

-- Add build modes
add_rules("mode.debug", "mode.release")

-- Platform specific settings
if is_plat("windows") then
    add_defines("WIN32", "_WINDOWS", "_CRT_SECURE_NO_WARNINGS")
    add_syslinks("kernel32", "user32", "advapi32")
    add_cxxflags("/EHsc")
    
    if is_mode("release") then
        add_cxxflags("/O2")
        set_optimize("fastest")
    end
elseif is_plat("linux") then
    add_syslinks("dl")
    
    if is_mode("release") then
        add_cxxflags("-O3")
        set_optimize("fastest")
    end
end

-- Debug/Release settings
if is_mode("debug") then
    add_defines("DEBUG")
    set_symbols("debug")
    set_optimize("none")
else
    add_defines("NDEBUG")
    set_symbols("hidden")
    set_strip("all")
end

-- Main DLL Generator executable
target("dll_generator")
    set_kind("binary")
    add_files("src/main.cpp")
    set_targetdir(".")
    
    after_build(function (target)
        print("Successfully built: " .. target:targetfile())
        print("Usage: dll_generator <input_dll_path> <output_directory>")
        print("Example: dll_generator C:\\Windows\\System32\\kernel32.dll ./output")
    end)