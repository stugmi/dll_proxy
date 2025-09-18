-- XMake build configuration for ReflectivedxgiLoader
set_project("ReflectivedxgiLoader")
set_version("1.0.0")
set_xmakever("2.7.1")

-- Set C++ standard
set_languages("cxx17")

-- Set build modes
add_rules("mode.debug", "mode.release")

-- Windows specific settings
if is_os("windows") then
    add_defines("WIN32", "_WINDOWS")
    add_syslinks("kernel32", "user32")
    add_cxxflags("/EHsc")
end

-- DLL Analyzer executable
target("dll_analyzer")
    set_kind("binary")
    add_files("main.cpp")
    set_targetdir("bin")

-- Reflective loader static library
target("dxgi_loader")
    set_kind("static")
    add_files("ReflectivedxgiLoader.cpp")
    add_headerfiles("ReflectivedxgiLoader.h")
    set_targetdir("lib")

-- Example usage executable
target("example")
    set_kind("binary")
    add_files("example_usage.cpp")
    add_deps("dxgi_loader")
    set_targetdir("bin")

-- Package configuration
includes("@builtin/xpack")
xpack("dxgi_reflective_loader")
    set_formats("zip", "tar.gz")
    set_basename("ReflectivedxgiLoader-$(os)-$(arch)")
    add_targets("dll_analyzer", "dxgi_loader", "example")
    add_files("README.md")
