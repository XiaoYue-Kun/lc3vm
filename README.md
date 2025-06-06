# LC-3 Virtual Machine

A cross-platform LC-3 (Little Computer 3) virtual machine implementation with basic debugging capabilities, written in C.
Based on [lc3-vm tutorial](https://github.com/justinmeiners/lc3-vm).

## Features

- **Full LC-3 Instruction Set**: Supports all standard LC-3 operations including arithmetic, logic, memory operations, and control flow
- **Interactive Debugger**: Step-by-step execution with breakpoints and register inspection
- **Cross-Platform**: (Hopefully) Works on Windows, Linux, and macOS
- **Memory-Mapped I/O**: Keyboard input support with proper buffering control
- **TRAP Routines**: Complete implementation of LC-3 TRAP operations for I/O

## Supported Instructions

| Operation | Description |
|-----------|-------------|
| `BR` | Branch (conditional) |
| `ADD` | Addition |
| `LD` | Load |
| `ST` | Store |
| `JSR` | Jump to Subroutine |
| `AND` | Bitwise AND |
| `LDR` | Load Register |
| `STR` | Store Register |
| `NOT` | Bitwise NOT |
| `LDI` | Load Indirect |
| `STI` | Store Indirect |
| `JMP` | Jump |
| `LEA` | Load Effective Address |
| `TRAP` | System Call |

## TRAP Routines

- `x20` GETC - Get character from keyboard
- `x21` OUT - Output a character
- `x22` PUTS - Output a string
- `x23` IN - Prompt for and input a character
- `x24` PUTSP - Output a string (packed)
- `x25` HALT - Halt execution

## Building

### Prerequisites
- GCC or any C compiler
- Standard C library

### Compilation
```bash
gcc -o lc3vm lc3vm.c
```

For Windows with MinGW:
```bash
gcc -o lc3vm.exe lc3vm.c
```

## Usage

### Running a Program
```bash
./lc3vm [program.obj]
```

You can load multiple object files:
```bash
./lc3vm program1.obj program2.obj
```

### Interactive Mode
If no files are specified, the VM starts in interactive mode:
```
lc3vm by Akatsuki. Enter "help" or "h" to see commands.
lc3vm> 
```

## Debugger Commands

| Command | Alias | Description |
|---------|-------|-------------|
| `load <file1> [file2...]` | `l` | Load LC-3 object file(s) |
| `set <reg> <value>` | `s` | Set register value (e.g., `set R0 x1234`) |
| `reset_reg` | `r` | Reset R0-R7 to x0000 |
| `lookup` | | Display all register values |
| `breakpoint <addr1> [addr2...]` | `b` | Toggle breakpoint(s) at address(es) |
| `step` | | Execute one instruction |
| `next` | `n` | Execute until next line (step over subroutines) |
| `continue` | `c` | Continue execution until breakpoint or halt |
| `help` | `h` | Show available commands |
| `quit` | `q` | Exit the simulator |

### Examples

**Load and run a program:**
```
lc3vm> load hello_world.obj
Loaded file: hello_world.obj
Set PC to x3000
lc3vm> continue
```

**Set a breakpoint and debug:**
```
lc3vm> breakpoint x3005
Set breakpoint at x3005
lc3vm> continue
Stopped at x3005
lc3vm> lookup
Registers:
  R0 x0065 | R1 x0000 | R2 x0000 | R3 x0000
  R4 x0000 | R5 x0000 | R6 x0000 | R7 x3001
  PC x3005 | IR x1401 | COND 001
```

**Set register values:**
```
lc3vm> set R0 xFF00
Set R0 to xFF00
lc3vm> set R1 x1234
Set R1 to x1234
```

## Architecture Details

- **Memory**: 65,536 (2^16) 16-bit words
- **Registers**: 8 general-purpose registers (R0-R7), PC, and condition codes
- **Addressing**: 16-bit address space
- **Word Size**: 16 bits
- **Condition Codes**: Negative (N), Zero (Z), Positive (P)

## File Format

The VM expects LC-3 object files in binary format with:
- First word: Origin address (where to load the program)
- Subsequent words: Program instructions and data
- All values stored in big-endian format (should be working with any lc3 assembler)

## Error Handling

The VM provides clear error messages for:
- Invalid instructions
- Memory access violations
- File loading errors
- Invalid debugger commands
- Register/address format errors

## License

This project is open source. Please check the license file for details.

## Author

Created by Akatsuki

---

**Note**: This LC-3 VM is designed for educational purposes and debugging LC-3 assembly programs. It provides a faithful implementation of the LC-3 architecture as described in "Introduction to Computing Systems" by Patt and Patel.