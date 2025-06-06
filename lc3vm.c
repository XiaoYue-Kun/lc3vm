#ifdef _WIN32
    #include <stdio.h>
    #include <stdint.h>
    #include <signal.h>
    /* windows only */
    #include <Windows.h>
    #include <conio.h>  // _kbhit

    HANDLE hStdin = INVALID_HANDLE_VALUE;
    DWORD fdwMode, fdwOldMode;

    void disable_input_buffering()
    {
        hStdin = GetStdHandle(STD_INPUT_HANDLE);
        GetConsoleMode(hStdin, &fdwOldMode); /* save old mode */
        fdwMode = fdwOldMode
                ^ ENABLE_ECHO_INPUT  /* no input echo */
                ^ ENABLE_LINE_INPUT; /* return when one or
                                        more characters are available */
        SetConsoleMode(hStdin, fdwMode); /* set new mode */
        FlushConsoleInputBuffer(hStdin); /* clear buffer */
    }

    void restore_input_buffering()
    {
        SetConsoleMode(hStdin, fdwOldMode);
    }

    uint16_t check_key()
    {
        return WaitForSingleObject(hStdin, 1000) == WAIT_OBJECT_0 && _kbhit();
    }

#endif

#if defined(__linux__) || defined(__APPLE__)
    #include <stdio.h>
    #include <stdint.h>
    #include <signal.h>
    /* unix only */
    #include <stdlib.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <sys/time.h>
    #include <sys/types.h>
    #include <sys/termios.h>
    #include <sys/mman.h>
    
    struct termios original_tio;

    void disable_input_buffering()
    {
        tcgetattr(STDIN_FILENO, &original_tio);
        struct termios new_tio = original_tio;
        new_tio.c_lflag &= ~ICANON & ~ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
    }

    void restore_input_buffering()
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &original_tio);
    }

    uint16_t check_key()
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 0;
        return select(1, &readfds, NULL, NULL, &timeout) != 0;
    }
#endif

#define MEMORY_MAX (1<<16)
uint16_t memory[MEMORY_MAX];

enum REGISTERS {
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6,
    R_R7,
    R_PC,
    R_COND,
    R_COUNT
};
uint16_t reg[R_COUNT];

enum OPERATIONS {
    OP_BR = 0,
    OP_ADD,
    OP_LD,
    OP_ST,
    OP_JSR,
    OP_AND,
    OP_LDR,
    OP_STR,
    OP_RTI,
    OP_NOT,
    OP_LDI,
    OP_STI,
    OP_JMP,
    OP_RES,
    OP_LEA,
    OP_TRAP
};

enum FLAGS {
    FL_POS = 1<<0,
    FL_ZRO = 1<<1,
    FL_NEG = 1<<2,
};

enum TRAP {
    TRAP_GETC = 0x20,
    TRAP_OUT = 0x21,
    TRAP_PUTS = 0x22,
    TRAP_IN = 0x23,
    TRAP_PUTSP = 0X24,
    TRAP_HALT = 0x25
};

enum MEMORY_MAPPED_REGISTERS {
    KBSR = 0xFE00,
    KBDR = 0xFE02
};

void mem_write(uint16_t val, uint16_t address){
    memory[address] = val;
}

uint16_t mem_read(uint16_t address){
    if(address == KBSR){
        if(check_key()){
            memory[KBSR] = (1 << 15);
            memory[KBDR] = getchar();
        }
        else{
            memory[KBSR] = 0;
        }
    }
    return memory[address];
}
uint16_t sign_extend(uint16_t x, int bit_count){
    if((x >> (bit_count - 1)) & 1){
        x |= (0xFFFF << bit_count);
    }
    return x;
}

void set_cc(uint16_t r){
    if(reg[r] == 0){
        reg[R_COND] = FL_ZRO;
    }
    else if(reg[r] >> 15){
        reg[R_COND] = FL_NEG;
    }
    else{
        reg[R_COND] = FL_POS;
    }
}

void handle_interrupt(int signal)
{
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

uint16_t swap16(uint16_t x){
    return (x << 8) | (x >> 8);
}

void read_image_file(FILE *file){
    uint16_t origin;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);
    reg[R_PC] = origin;

    uint16_t max_read = MEMORY_MAX - origin;
    uint16_t *p = memory + origin;
    size_t read = fread(p, sizeof(uint16_t), max_read, file);

    while(read-- > 0){
        *p = swap16(*p);
        ++p;
    }
}

int read_image(const char* image_path){
    FILE* file = fopen(image_path, "rb");
    if(!file){
        puts("Unable to open file.");
        return 0;
    }
    read_image_file(file);
    fclose(file);
    return 1;
}

int main(int argc, const char* argv[]){
    if(argc < 2){
        printf("lc3 [image-file1] ...\n");
        exit(2);
    }
    for(int i=1; i<argc; i++){
        if(!read_image(argv[i])){
            printf("failed to load image: %s\n", argv[i]);
            exit(1);
        }
    }
    printf("set pc to x%x\n", reg[R_PC]);

    reg[R_PC] = 0x3000;
    reg[R_COND] = FL_ZRO;

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    int running = 1;
    while(running){
        uint16_t instr = mem_read(reg[R_PC]++);
        uint16_t op = instr >> 12;

        switch(op){
            case OP_BR:
            {
                uint16_t cond_flag = (instr >> 9) & 0x7;

                if(cond_flag & reg[R_COND]){
                    uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                    reg[R_PC] = reg[R_PC] + PC_offset;
                }
                break;
            }
            case OP_ADD:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t SR1 = (instr >> 6) & 0x7;
                uint16_t imm_flag = (instr >> 5) & 0x1;
                if(imm_flag){
                    uint16_t imm5 = sign_extend(instr & 0x1F, 5);
                    reg[DR] = reg[SR1] + imm5;
                }
                else{
                    uint16_t SR2 = instr & 0x7;
                    reg[DR] = reg[SR1] + reg[SR2];
                }
                set_cc(DR);
                break;
            }
            
            case OP_LD:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                reg[DR] = mem_read(reg[R_PC] + PC_offset);
                set_cc(DR);   
                break;
            }
            
            case OP_ST:
            {
                uint16_t SR = (instr >> 9) & 0x7;
                uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                mem_write(reg[SR], reg[R_PC] + PC_offset); 
                break;
            }
            
            case OP_JSR:
            {
                uint16_t flag = (instr >> 11) & 0x1;
                reg[R_R7] = reg[R_PC];
                if(flag){
                    uint16_t PC_offset = sign_extend(instr & 0x7FF, 11);
                    reg[R_PC] = reg[R_PC] + PC_offset;
                }
                else{
                    uint16_t BaseR = (instr >> 6) & 0x7;
                    reg[R_PC] = reg[BaseR];
                }
                break;
            }
            
            case OP_AND:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t SR1 = (instr >> 6) & 0x7;
                uint16_t imm_flag = (instr >> 5) & 0x1;
                if(imm_flag){
                    uint16_t imm5 = sign_extend(instr & 0x1F, 5);
                    reg[DR] = reg[SR1] & imm5;
                }
                else{
                    uint16_t SR2 = instr & 0x7;
                    reg[DR] = reg[SR1] & reg[SR2];
                }
                set_cc(DR);
                break;
            }
            
            case OP_LDR:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t BaseR = (instr >> 6) & 0x7;
                uint16_t offset = sign_extend(instr & 0x3F, 6);
                reg[DR] = mem_read(reg[BaseR] + offset);
                set_cc(DR);
                break;
            }
            
            case OP_STR:
            {
                uint16_t SR = (instr >> 9) & 0x7;
                uint16_t BaseR = (instr >> 6) & 0x7;
                uint16_t offset = sign_extend(instr & 0x3F, 6);
                mem_write(reg[SR], reg[BaseR] + offset);
                break;
            }
            case OP_RTI:
            {
                abort();
                break;
            }
            case OP_NOT:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t SR = (instr >> 6) & 0x7;
                reg[DR] = ~reg[SR];
                set_cc(DR);
                break;
            }
            case OP_LDI:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                reg[DR] = mem_read(mem_read(reg[R_PC] + PC_offset));
                set_cc(DR);
                break;
            }
            case OP_STI:
            {
                uint16_t SR = (instr >> 9) & 0x7;
                uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                mem_write(reg[SR], mem_read(reg[R_PC] + PC_offset));
                break;
            }
            case OP_JMP:
            {
                uint16_t BaseR = (instr >> 6) & 0x7;
                reg[R_PC] = reg[BaseR];
                break;
            }
            case OP_RES:
            {
                abort();
                break;
            }
            case OP_LEA:
            {
                uint16_t DR = (instr >> 9) & 0x7;
                uint16_t PC_offset = sign_extend(instr & 0x1FF, 9);
                reg[DR] = reg[R_PC] + PC_offset;
                set_cc(DR);
                break;
            }
            case OP_TRAP:
            {
                reg[R_R7] = reg[R_PC];
                switch(instr & 0xFF){
                    case TRAP_GETC:
                    {
                        reg[R_R0] = (uint16_t)getchar();
                        set_cc(R_R0);
                        break;
                    }
                    case TRAP_OUT:
                    {
                        putc((char) reg[R_R0], stdout);
                        fflush(stdout);
                        break;
                    }
                    case TRAP_PUTS:
                    {
                        uint16_t* c = memory + reg[R_R0];
                        while(*c){
                            putc((char) *c, stdout);
                            c++;
                        }
                        fflush(stdout);
                        break;
                    }
                    case TRAP_IN:
                    {
                        puts("Enter a character: ");
                        char c = getchar();
                        putc(c, stdout);
                        fflush(stdout);
                        reg[R_R0] = (uint16_t) c;
                        break;
                    }
                    case TRAP_PUTSP:
                    {
                        uint16_t *c = memory + reg[R_R0];
                        while(*c){
                            putc((char) *c, stdout);
                            putc((char) (*c >> 8), stdout);
                            c++;
                        }
                        fflush(stdout);
                        break;
                    }
                    case TRAP_HALT:
                    {
                        puts("HALT");
                        fflush(stdout);
                        running = 0;
                        break;
                    }
                }
                break;
            }
            default:
                abort();
                break;
        }
    }
    restore_input_buffering();
}