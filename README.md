## Usage

Build using xmake


install xmake:
```powershell
irm https://xmake.io/psget.text | iex
```


build:
```powershell
❯❯ dll_gen git:(main) xmake b
Successfully built: .\dll_generator.exe
Usage: dll_generator <input_dll_path> <output_directory>
Example: dll_generator C:\Windows\System32\kernel32.dll ./output
```

run and build:
```pwsh
❯❯ dll_gen git:(main) xmake run dll_generator C:\Windows\System32\dxgi.dll ./output
Successfully built: .\dll_generator.exe
Usage: dll_generator <input_dll_path> <output_directory>
Example: dll_generator C:\Windows\System32\kernel32.dll ./output
=== DLL Proxy/Generator ===
[+] Successfully loaded DLL: C:\Windows\System32\dxgi.dll
[+] Entry Point: 0x0x6d240
[+] Image Base: 0x0x180000000

[+] Found 20 exported functions (named):
[*]   - ApplyCompatResolutionQuirking (Ordinal: 1)
[*]   - CompatString (Ordinal: 2)
[*]   - CompatValue (Ordinal: 3)
[*]   - CreateDXGIFactory (Ordinal: 10)
[*]   - CreateDXGIFactory1 (Ordinal: 11)
[*]   - CreateDXGIFactory2 (Ordinal: 12)
[*]   - DXGID3D10CreateDevice (Ordinal: 13)
[*]   - DXGID3D10CreateLayeredDevice (Ordinal: 14)
[*]   - DXGID3D10GetLayeredDeviceSize (Ordinal: 15)
[*]   - DXGID3D10RegisterLayers (Ordinal: 16)
[*]   - DXGIDeclareAdapterRemovalSupport (Ordinal: 17)
[*]   - DXGIDisableVBlankVirtualization (Ordinal: 18)
[*]   - DXGIDumpJournal (Ordinal: 4)
[*]   - DXGIGetDebugInterface1 (Ordinal: 19)
[*]   - DXGIReportAdapterConfiguration (Ordinal: 20)
[*]   - PIXBeginCapture (Ordinal: 5)
[*]   - PIXEndCapture (Ordinal: 6)
[*]   - PIXGetCaptureState (Ordinal: 7)
[*]   - SetAppCompatStringPointer (Ordinal: 8)
[*]   - UpdateHMDEmulationStatus (Ordinal: 9)


[+] Parsing import table:
[*]   - msvcp_win.dll (17 functions)
[*]   - api-ms-win-crt-string-l1-1-0.dll (5 functions)
[*]   - api-ms-win-crt-math-l1-1-0.dll (1 functions)
[*]   - api-ms-win-crt-runtime-l1-1-0.dll (2 functions)
[*]   - api-ms-win-crt-private-l1-1-0.dll (56 functions)
[*]   - ntdll.dll (56 functions)
[*]   - win32u.dll (3 functions)
[*]   - api-ms-win-core-libraryloader-l1-2-0.dll (11 functions)
[*]   - api-ms-win-core-synch-l1-1-0.dll (25 functions)
[*]   - api-ms-win-core-heap-l1-1-0.dll (4 functions)
[*]   - api-ms-win-core-errorhandling-l1-1-0.dll (5 functions)
[*]   - api-ms-win-core-threadpool-l1-2-0.dll (9 functions)
[*]   - api-ms-win-core-processthreads-l1-1-0.dll (9 functions)
[*]   - api-ms-win-core-localization-l1-2-0.dll (1 functions)
[*]   - api-ms-win-core-debug-l1-1-0.dll (4 functions)
[*]   - api-ms-win-core-handle-l1-1-0.dll (4 functions)
[*]   - api-ms-win-core-string-l1-1-0.dll (2 functions)
[*]   - api-ms-win-security-base-l1-1-0.dll (16 functions)
[*]   - api-ms-win-core-heap-l2-1-0.dll (2 functions)
[*]   - api-ms-win-core-synch-l1-2-1.dll (1 functions)
[*]   - api-ms-win-core-errorhandling-l1-1-2.dll (1 functions)
[*]   - api-ms-win-core-version-l1-1-0.dll (3 functions)
[*]   - api-ms-win-core-libraryloader-l1-2-1.dll (2 functions)
[*]   - api-ms-win-core-string-obsolete-l1-1-0.dll (3 functions)
[*]   - api-ms-win-core-profile-l1-1-0.dll (2 functions)
[*]   - api-ms-win-core-sysinfo-l1-1-0.dll (4 functions)
[*]   - api-ms-win-core-registry-l1-1-0.dll (11 functions)
[*]   - api-ms-win-core-synch-l1-2-0.dll (3 functions)
[*]   - api-ms-win-core-quirks-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-psapi-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-util-l1-1-0.dll (2 functions)
[*]   - api-ms-win-core-atoms-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-version-l1-1-1.dll (2 functions)
[*]   - api-ms-win-core-interlocked-l1-1-0.dll (2 functions)
[*]   - api-ms-win-core-processthreads-l1-1-1.dll (4 functions)
[*]   - api-ms-win-core-memory-l1-1-0.dll (4 functions)
[*]   - api-ms-win-core-apiquery-l1-1-0.dll (1 functions)
[*]   - KERNELBASE.dll (1 functions)
[*]   - api-ms-win-crt-time-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-file-l1-1-0.dll (6 functions)
[*]   - api-ms-win-core-path-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-shlwapi-obsolete-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-kernel32-legacy-ansi-l1-1-0.dll (1 functions)
[*]   - api-ms-win-core-delayload-l1-1-1.dll (1 functions)
[*]   - api-ms-win-core-delayload-l1-1-0.dll (1 functions)

[+] Generated ./output\dxgi.def
[+] Generated ./output\dxgi.cpp
[+] Generated ./output\xmake.lua
[+] Template generation complete!
```