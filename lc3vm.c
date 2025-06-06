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
#define MAX_INPUT 512
#define MAX_ARGS 32
uint16_t memory[MEMORY_MAX];
uint16_t breakpoint[MEMORY_MAX];
int file_loaded = 0;
uint16_t prev_instr = 0;

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

enum RUN_TYPE{
    STEP,
    NEXT,
    CONTINUE,
};

typedef struct {
    char* command;
    char **args;
    int arg_count;
} Command;

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

int run_instruction(int run_type){
    // return 0: halt

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    int running = 1;
    int subroutine = 0;
    uint16_t ret_addr = 0xFFFF;
    while(running){
        
        uint16_t instr = mem_read(reg[R_PC]++);
        prev_instr = instr;
        uint16_t op = instr >> 12;
        if (reg[R_PC] == 0){
            printf("Runtime Error: Running outside memory\n");
            return 0;
        }
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
                subroutine = 1;
                ret_addr = reg[R_R7];
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
                printf("Runtime Error: Unsupported instruction RTI\n");
                restore_input_buffering();
                return -1;
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
                if(BaseR == R_R7 && reg[R_PC] == ret_addr){
                    subroutine = 0;
                    ret_addr = 0xFFFF;
                    if(run_type == NEXT){
                        running = 0;
                    }
                }
                break;
            }
            case OP_RES:
            {
                printf("Runtime Error: Unsupported instruction RES\n");
                restore_input_buffering();
                return -1;
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
                        puts("---HALT---");
                        fflush(stdout);
                        running = 0;
                        restore_input_buffering();
                        return 0;
                    }
                }
                break;
            }
            default:
                printf("Runtime Error: Unrecognized instruction\n");
                restore_input_buffering();
                return -1;
                break;
            
        }
        if(run_type == STEP || breakpoint[reg[R_PC]] || (run_type == NEXT && subroutine == 0)){
            running = 0;
        }
    }
    restore_input_buffering();
    return 1;
}

int is_hex(char c){
    return ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f'));
}

uint16_t hex_char_to_int(char c){
    if(!is_hex(c))                  return 0;
    if(c >= '0' && c <= '9')        return (uint16_t) c - '0';
    else if((c >= 'A' && c <= 'F')) return (uint16_t) c - 'A' + 10;
    else                            return (uint16_t) c - 'a' + 10;
}

char* skip_whitespace(char *str) {
    while (*str && isspace(*str)) str++;
    return str;
}

char* parse_token(char **input, char *token_buf, size_t buf_size) {
    char *p = skip_whitespace(*input);
    char *token = token_buf;
    int in_quotes = 0;
    int escaped = 0;
    size_t len = 0;
    
    if (!*p) {
        *input = p;
        return NULL;
    }
    
    while (*p && len < buf_size - 1) {
        if (escaped) {
            *token++ = *p++;
            len++;
            escaped = 0;
        } else if (*p == '\\') {
            escaped = 1;
            p++;
        } else if (*p == '"') {
            in_quotes = !in_quotes;
            p++;
        } else if (!in_quotes && isspace(*p)) {
            break;
        } else {
            *token++ = *p++;
            len++;
        }
    }
    
    *token = '\0';
    *input = p;
    
    return len > 0 ? token_buf : NULL;
}

Command parse_command(char *input) {
    Command cmd = {0};
    char token_buf[256];
    char **args = (char **) malloc(MAX_ARGS * sizeof(char*));
    int count = 0;
    char *p = input;
    
    // Remove trailing newline
    input[strcspn(input, "\n")] = 0;
    
    // Parse command
    char *command_token = parse_token(&p, token_buf, sizeof(token_buf));
    if (command_token) {
        cmd.command = strdup(command_token);
        
        // Parse arguments
        char *arg_token;
        while ((arg_token = parse_token(&p, token_buf, sizeof(token_buf))) != NULL 
               && count < MAX_ARGS - 1) {
            args[count] = strdup(arg_token);
            count++;
        }
    }
    
    args[count] = NULL;
    cmd.args = args;
    cmd.arg_count = count;
    
    return cmd;
}

void free_command(Command *cmd) {
    if (cmd->command) {
        free(cmd->command);
        cmd->command = NULL;
    }
    
    for (int i = 0; i < cmd->arg_count; i++) {
        if (cmd->args[i]) {
            free(cmd->args[i]);
        }
    }
    free(cmd->args);
    cmd->args = NULL;
    cmd->arg_count = 0;
}

void handle_command(Command cmd) {
    if (!cmd.command) return;
    
    if (strcmp(cmd.command, "load") == 0 || strcmp(cmd.command, "l") == 0) {
        if (cmd.arg_count >= 1) {
            for(int i = 0; i < cmd.arg_count; i++){
                printf("Loading file: %s\n", cmd.args[i]);
                read_image(cmd.args[i]);
            }
            printf("Set PC to x%x\n", reg[R_PC]);
        } else {
            printf("Error: load command requires a filename\n");
        }
    } else if (strcmp(cmd.command, "set") == 0 || strcmp(cmd.command, "s") == 0) {
        if (cmd.arg_count == 2) {
            if((cmd.args[0][0] == 'R' || cmd.args[0][0] == 'r') && (cmd.args[0][1] >= '0' && cmd.args[0][1] <= '7')){
                if(cmd.args[1][0] == 'x' || cmd.args[1][0] == 'X'){
                    cmd.args[1]++;
                }
                int len = 0;
                while(cmd.args[1][len] != '\0'){
                    if(!is_hex(cmd.args[1][len])){
                        printf("Error: invalid value\n");
                        return;
                    }
                    len++;
                }
                if (len > 4){
                    printf("Error: value out of range\n");
                    return;
                }
                uint16_t hex = 0;
                for(int i = 0; i < len; i++){
                    hex <<= 4;
                    hex += hex_char_to_int(cmd.args[1][0]);
                    cmd.args[1]++;
                }
                reg[cmd.args[0][1] - '0'] = hex;
                printf("Set R%c to x%x\n", cmd.args[0][1], hex);
            }
            else{
                printf("Error: invalid register\n");
            }
        } else {
            printf("Error: set command requires exactly one register and one value\n");
        }
    } else if (strcmp(cmd.command, "reset_reg") == 0 || strcmp(cmd.command, "r") == 0) {
        if(cmd.arg_count != 0){
            printf("Error: Reset register should not have any argument\n");
            return;
        }
        reg[R_R0] = 0;
        reg[R_R1] = 0;
        reg[R_R2] = 0;
        reg[R_R3] = 0;
        reg[R_R4] = 0;
        reg[R_R5] = 0;
        reg[R_R6] = 0;
        reg[R_R7] = 0;
        printf("Set R0-R7 to x0000\n");
    } else if (strcmp(cmd.command, "lookup") == 0) {
        printf("Registers:\n");
        printf("  R0 x%.4x | R1 x%.4x | R2 x%.4x | R3 x%.4x\n", reg[R_R0], reg[R_R1], reg[R_R2], reg[R_R3]);
        printf("  R4 x%.4x | R5 x%.4x | R6 x%.4x | R7 x%.4x\n", reg[R_R4], reg[R_R5], reg[R_R6], reg[R_R7]);
        printf("  PC x%.4x | IR x%.4x | COND %1d%1d%1d\n", reg[R_PC], prev_instr, (reg[R_COND] >> 2) & 0x1, (reg[R_COND] >> 1) & 0x1, reg[R_COND] & 0x1);
    } else if (strcmp(cmd.command, "breakpoint") == 0 || strcmp(cmd.command, "b") == 0) {
        for(int i = 0; i < cmd.arg_count; i++){
            if(cmd.args[i][0] == 'x' || cmd.args[i][0] == 'X'){
                cmd.args[i]++;
            }
            int len = 0;
            while(cmd.args[i][len] != '\0'){
                if(!is_hex(cmd.args[i][len])){
                    printf("Error: invalid address x%s\n", cmd.args[i]);
                    return;
                }
                len++;
            }
            if (len > 4){
                printf("Error: address x%s out of range\n", cmd.args[i]);
                return;
            }
            uint16_t hex = 0;
            for(int j = 0; j < len; j++){
                hex <<= 4;
                hex += hex_char_to_int(cmd.args[i][0]);
                cmd.args[i]++;
            }
            if (breakpoint[hex]){
                breakpoint[hex] = 0;
                printf("Remove breakpoint at x%.4x\n", hex);
            }
            else{
                breakpoint[hex] = 1;
                printf("Set breakpoint at x%.4x\n", hex);
            }
        }
    } else if (strcmp(cmd.command, "step") == 0) {
        if(run_instruction(STEP)){
            printf("Stopped at x%x\n", reg[R_PC]);
        }
    } else if (strcmp(cmd.command, "next") == 0 || strcmp(cmd.command, "n") == 0) {
        if(run_instruction(NEXT)){
            printf("Stopped at x%x\n", reg[R_PC]);
        }
    } else if (strcmp(cmd.command, "continue") == 0 || strcmp(cmd.command, "c") == 0) {
        if(run_instruction(CONTINUE)){
            printf("Stopped at x%x\n", reg[R_PC]);
        }
    } else if (strcmp(cmd.command, "help") == 0 || strcmp(cmd.command, "h") == 0) {
        printf("Available commands:\n");
        printf("  load <filename1> <filename2> ...  - Load a file\n");
        printf("  set <reg> <value>                 - Set register\n");
        printf("  reset_reg                         - Reset R0-R7 to x0000\n");
        printf("  lookup                            - Lookup register values\n");
        printf("  breakpoint <addr1> <addr2> ...    - Set/Remove breakpoint\n");
        printf("  step\n");
        printf("  next\n");
        printf("  continue\n");
        printf("  help                              - Show this help\n");
        printf("  quit                              - Exit simulator\n");
    } else if (strcmp(cmd.command, "quit") == 0 || strcmp(cmd.command, "q") == 0){
        printf("Goodbye.\n");
        // free_command(cmd);
        exit(0);
    } else {
        printf("Unknown command: %s\n", cmd.command);
        printf("Type 'help' for available commands.\n");
    }
    
}

int main(int argc, const char* argv[]){
    printf("lc3vm by Akatsuki. Enter \"help\" or \"h\" to see commands.\n");
    if(argc >= 2){
        for(int i=1; i<argc; i++){
            if(!read_image(argv[i])){
                printf("failed to load image: %s\n", argv[i]);
                exit(1);
            }
        }
        printf("set pc to x%x\n", reg[R_PC]);
    }

    reg[R_COND] = FL_ZRO;

    char command[255];

    while(1){
        printf("lc3vm> ");
        fgets(command, 255, stdin);
        handle_command(parse_command(command));
    }
    
    
}