#include <stdio.h>
#include <inttypes.h>
#include <capstone/capstone.h>

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// TODO: convert to C to reduce libc++ static link size

// Linux:
// g++ MDasm2.cpp -lcapstone -oMDasm2.elf -O3 -march=x86-64-v2 -static

// Windows (on Linux):
// x86_64-w64-mingw32-g++ MDasm2.cpp -lcapstone -lssp -oMDasm2.exe -O3 -march=x86-64-v2 -static -L ~/Downloads/capstone-5.0.1 -I ~/Downloads/capstone-5.0.1/include

// Compiling capstone for Linux:
// cd ~/Downloads/capstone-5.0.1
// CFLAGS="-O3 -march=x86-64-v2" V=1 ./make.sh
// sudo ./make.sh install

// Compiling capstone for Windows (on Linux):
// cd ~/Downloads/capstone-5.0.1
// CFLAGS="-O3 -march=x86-64-v2 -fno-stack-protector" V=1 ./make.sh cygwin-mingw64

#define PERMUTER

typedef unsigned char BYTE;

// #define CODE "\x00\x00\x00\x00\x00"

// FILE _iob[] = { *stdin, *stdout, *stderr };
//
// #pragma comment(lib, "legacy_stdio_definitions.lib")

// extern "C" FILE * __cdecl __iob_func(void)
// {
//     return _iob;
// }

typedef struct  Params
{
    bool        offsets;
    bool        bytes;
    bool        reloc;
    bool        code;
} Params;

Params          g_params = { 0 };

/*
enum class PsyqOpcode : uint8_t {
    END = 0,
    BYTES = 2,
    SWITCH = 6,
    ZEROES = 8,
    RELOCATION = 10,
    EXPORTED_SYMBOL = 12,
    IMPORTED_SYMBOL = 14,
    SECTION = 16,
    LOCAL_SYMBOL = 18,
    FILENAME = 28,
    PROGRAMTYPE = 46,
    UNINITIALIZED = 48,
};

enum class PsyqRelocType : uint8_t {
    REL32 = 16,
    REL26 = 74,
    HI16 = 82,
    LO16 = 84,
    GPREL16 = 100,
};

enum class PsyqExprOpcode : uint8_t {
    VALUE = 0,
    SYMBOL = 2,
    SECTION_BASE = 4,
    SECTION_START = 12,
    SECTION_END = 22,
    ADD = 44,
    SUB = 46,
    DIV = 50,
};
*/
/*
typedef struct  Section
{
//    int         index;
    int         groupe;
    char        name[256];
} Section;

Section g_sections[1024] = { 0 };
*/
typedef struct  Reloc
{
    char        type[32];
    char        name[256];
    char        op;
    char        expr[512];
} Reloc;

Reloc g_relocs[2048] = { 0 };

char g_symbols[1024][256] = { 0 };

typedef struct  Section
{
    short       index;
    short       groupeId;
    unsigned char      alignment;
    unsigned char      nameLen;
    char        name[];
} Section;
Section         *g_sections[1024] = { 0 };
/*
typedef struct  Symbol
{
    short       number;
    short       section;
    int         offset;
    u_char      nameLen;
    char        name[];
} Symbol;
Symbol          *g_symbols[1024] = { 0 };
*/
typedef struct  Code
{
    short       size;
    char        code[];
} Code;
int             g_totalCodes = 0;
Code            *g_codes[512] = { 0 };

//! Byte swap short
int16_t swap_int16(int16_t val)
{
    return (val << 8) | ((val >> 8) & 0xFF);
}


BYTE    *readPsyqObjSymbols(BYTE *ptr, BYTE *buffer, int file_size)
{
    int dims;
    while (ptr - buffer < file_size)
    {
        //    printf("OPCODE: 0x%-2x - %-2d at offset 0x%x\n", *ptr, *ptr, ptr - buffer);
        switch (*ptr++)
        {
        case 0x30:  // 48 - XBSS symbol number %lx .. size %lx in section %lx\n
            ptr += 2; // symbol number
            ptr += 2; // section
            ptr += 4; // size
            ptr += *ptr + 1; // symbol name
            break;



        case 0x10: // 16 - Section symbol number 1 '.rdata' in group 0 alignment 8
            ptr += 2; // section index
            ptr += 2; // groupe index
            ptr += 1; // alignment
            ptr += *ptr + 1; // section name
            break;
        case 0x1c: // 28 - file name
            ptr += 2; // file number
            ptr += *ptr + 1; // file name
            break;
        case 0x6:  // 6 - Switch
            ptr += 2; // section index
            break;
        case 0x8:  // 8 - Uninitialised data
            ptr += 4; // total bytes
            break;
        case 0x2:  // 2 - Code
            ptr += *(short*)ptr + 2; // code
            break;
        case 0x3a: // 58 - Set SLD linenum to 5 at offset 0 in file c
            ptr += 8;
            break;
        case 0x34: // 52 - Inc SLD linenum by byte 0 at offset 0
            ptr += 3;
            break;
        case 0x32: // 50 - Inc SLD linenum at offset 0
            ptr += 2;
            break;
        case 0x38: // 56 - Set SLD linenum to 14 at offset 1c
            ptr += 6;
            break;
        case 0xa:  // 10 - Patch type 74 at offset 2c with (sectbase(2)+$38)
            switch (*ptr)
            {
            case 16:  // REL32
            case 74:  // REL26
            case 82:  // HI16
            case 84:  // LO16
            case 100: // GPREL16
                break;
            }
            ptr += 1; // reloc type
            ptr += 2; // offset
            for (int i = 0; i < 1; i++)
            {
                switch (*ptr++)
                {
                case 0:   // VALUE
                    ptr += 4;
                    break;
                case 2:   // SYMBOL
                case 4:   // SECTION_BASE
                case 12:  // SECTION_START
                case 22:  // SECTION_END
                    ptr += 2;
                    break;
                case 44:  // ADD
                case 46:  // SUB
                case 50:  // DIV
                    i -= 2;
                    break;
                }
            }
            break;
        case 0x3c: // 60 - End SLD info at offset 0
            ptr += 2; // offset
            break;
        case 0xc:  // 12 - XDEF symbol number a 'CRC32_80020BB4' at offset 0 in section 2
            sprintf(g_symbols[*(short*)ptr], "%.*s\0", *(ptr + 8), ptr + 9);
        //    g_symbols[*(short*)ptr] = (Symbol*)ptr;
            ptr += 2; // symbol number
            ptr += 2; // section index
            ptr += 4; // offset
            ptr += *ptr + 1; // symbol name
            break;
        case 0xe:  // 14 - XREF symbol number 24 'GCL_ReadVector_80020A14'
            sprintf(g_symbols[*(short*)ptr], "%.*s\0", *(ptr + 2), ptr + 3);
            ptr += 2; // symbol number
            ptr += *ptr + 1; // symbol name
            break;
        case 0x52: // 82 - Def
            ptr += 2; // section
            ptr += 4; // value
            ptr += 2; // class
            ptr += 2; // type
            ptr += 4; // size
            ptr += *ptr + 1; // name
            break;
        case 0x54: // 84 - Def2 (arrays)
            ptr += 2; // section
            ptr += 4; // value
            ptr += 2; // class
            ptr += 2; // type
            ptr += 4; // size
            dims = *(short*)ptr;
            for (int i = 0; i <= dims; i++)
            {
                if (i == 0)
                {
                    ptr += 2; // dims
                }
                else
                {
                    ptr += 4; // dims
                }
            }
            if (dims && *ptr == 0)
            {
                ptr += 1; // padding ?
            }
            else
            {
                ptr += *ptr + 1; // tag (1st line)
            }
            ptr += *ptr + 1; // tag (2nd line)
            break;
        case 0x4a: // 74 - Function start
            ptr += 2; // section
            ptr += 4; // offset
            ptr += 2; // file
            ptr += 4; // start line
            ptr += 2; // frame reg
            ptr += 4; // frame size
            ptr += 2; // return pc reg
            ptr += 4; // mask
            ptr += 4; // mask offset
            ptr += *ptr + 1; // name
            break;
        case 0x4e: // 78 - Block start
            ptr += 2; // section
            ptr += 4; // offset
            ptr += 4; // start line
            break;
        case 0x50: // 80 - Block end
            ptr += 2; // section
            ptr += 4; // offset
            ptr += 4; // end line
            break;
        case 0x4c: // 76 - Function end
            ptr += 2; // section
            ptr += 4; // offset
            ptr += 4; // end line
            break;
        case 0:  // End of file
            break;
        default:
            ptr--;
            printf("Error111: unknown opcode 0x%x in obj file at offset 0x%x.\n", *ptr, ptr - buffer);
            exit(1);
        }
    }
    return ptr;
}

BYTE *readPsyqObj(char* objName, int *offsetStart, int *len)
{
    FILE* file = fopen(objName, "rb");
    if (!file)
    {
        printf("Error: Unable to open obj file %s\n", objName);
        exit(1);
    }

    // Get Filesize 
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);
//    printf("size of obj is: %d\n", file_size);

    // Allocate memory for buffer
    BYTE* buffer = new BYTE[file_size];

    // Fill Buffer
    fread(buffer, file_size, 1, file);
    fclose(file);

    // Read obj
    BYTE* ptr = buffer;
    short dims;

    Reloc *reloc;

    ptr += 3; // name (LNK)
    ptr += 1; // version (2)
    ptr += 2; // processor type (7)

    readPsyqObjSymbols(ptr, buffer, file_size);

    while (ptr - buffer < file_size)
    {
    //    printf("OPCODE: 0x%-2x - %-2d at offset 0x%x\n", *ptr, *ptr, ptr - buffer);
        switch (*ptr++)
        {
            case 0x30:  // 48 - XBSS symbol number %lx .. size %lx in section %lx\n
                ptr += 2; // symbol number
                ptr += 2; // section
                ptr += 4; // size
                ptr += *ptr + 1; // symbol name
                break;


            case 0x10: // 16 - Section symbol number 1 '.rdata' in group 0 alignment 8
            //    printf("section %d groupe %d align %d name %.*s\n", *(short*)ptr, *(short*)(ptr+2), *(ptr + 4), *(ptr + 5), (ptr + 6));
                g_sections[*(short*)ptr] = (Section*)ptr;
            //    sprintf(g_sections[*(short*)ptr].name, "%.*s\0", *(ptr + 5), ptr + 6);
                /*
                    short   index;
                    short   groupeId;
                    char    alignment;
                    char    *name;
                */
                ptr += 2; // section index
            //    g_sections[*(short*)ptr].groupe = *(short*)ptr;
                ptr += 2; // groupe index
                ptr += 1; // alignment
                ptr += *ptr + 1; // section name
                break;
            case 0x1c: // 28 - file name
                ptr += 2; // file number
            //    printf("file: %.*s\n", *ptr, ptr + 1);
                ptr += *ptr + 1; // file name
                break;
            case 0x6:  // 6 - Switch
                ptr += 2; // section index
                break;
            case 0x8:  // 8 - Uninitialised data
                ptr += 4; // total bytes
                break;
            case 0x2:  // 2 - Code
                g_codes[g_totalCodes++] = (Code*)ptr;
                *len = *(unsigned short*)ptr;
                ptr += 2; // len
                *offsetStart = ptr - buffer;
                ptr += *len; // mips code
                break;
            case 0x3a: // 58 - Set SLD linenum to 5 at offset 0 in file c
                ptr += 8;
                break;
            case 0x34: // 52 - Inc SLD linenum by byte 0 at offset 0
                ptr += 3;
                break;
            case 0x32: // 50 - Inc SLD linenum at offset 0
                ptr += 2;
                break;
            case 0x38: // 56 - Set SLD linenum to 14 at offset 1c
                ptr += 6;
                break;
            case 0xa:  // 10 - Patch type 74 at offset 2c with (sectbase(2)+$38)
                /*
                typedef struct  reloc
                {
                    enum        
                    {
                        eR_MIPS_32 = 16,
                        eR_MIPS_26 = 74,
                        eR_HI16 = 82,
                        eR_LO16 = 84,
                        eR_GPREL16 = 100,
                    }           type;
                }
                */
              //  g_relocs[*(short*)ptr].
                reloc = &g_relocs[*(short*)(ptr + 1) / 4];
             //   printf("Patch \n");
                switch (*ptr)
                {
                    case 16:  // REL32
                    //    printf("type R_MIPS_32 ");
                        sprintf(reloc->type, "R_MIPS_32\0");
                        break;
                    case 74:  // REL26
                    //    printf("type R_MIPS_26 ");
                        sprintf(reloc->type, "R_MIPS_26");
                        break;
                    case 82:  // HI16
                    //    printf("type R_HI16 ");
                        sprintf(reloc->type, "R_HI16");
                        break;
                    case 84:  // LO16
                    //    printf("type R_LO16 ");
                        sprintf(reloc->type, "R_LO16");
                        break;
                    case 100: // GPREL16
                    //    printf("type GPREL16 ");
                        sprintf(reloc->type, "GPREL16");
                        break;
                }
                ptr += 1; // reloc type
             //   printf("at offset %x ", *(short*)ptr);
                ptr += 2; // offset
                for (int i = 0; i < 1; i++)
                {
                    switch (*ptr++)
                    {
                        case 0:   // VALUE
                        //    printf("value %#x ", *(int*)ptr);
                            if (*reloc->expr)
                            {
                                sprintf(reloc->expr, "%s%c%x", reloc->expr, reloc->op, *(int*)ptr);
                            }
                            else
                            {
                                sprintf(reloc->expr, "%x", *(int*)ptr);
                            }
                            ptr += 4;
                            break;
                        case 2:   // SYMBOL
                        //    printf("symbol %s ", g_symbols[*(short*)ptr]);
                            if (*reloc->expr)
                            {
                                sprintf(reloc->expr, "%s%c%s", reloc->expr, reloc->op, g_symbols[*(short*)ptr]);
                            }
                            else
                            {
                                sprintf(reloc->expr, "%s", g_symbols[*(short*)ptr]);
                            }
                            ptr += 2;
                            break;
                        case 4:   // SECTION_BASE
                        //    printf("sectbase(%d) ", *(short*)ptr);
                        //    printf("%s ", g_sections[*(short*)ptr].name);
                            if (*reloc->expr)
                            {
                                sprintf(reloc->expr, "%s%c%.*s", reloc->expr, reloc->op, g_sections[*(short*)ptr]->nameLen, g_sections[*(short*)ptr]->name);
                            }
                            else
                            {
                                sprintf(reloc->expr, "%.*s", g_sections[*(short*)ptr]->nameLen, g_sections[*(short*)ptr]->name);
                            }
                            ptr += 2;
                            break;
                        case 12:  // SECTION_START
                        //    printf("sectstart(%d) ", *(short*)ptr);
                            ptr += 2;
                            break;
                        case 22:  // SECTION_END
                        //    printf("sectend(%d) ", *(short*)ptr);
                            ptr += 2;
                            break;
                        case 44:  // ADD
                        //    printf("ADD ");
                            reloc->op = '+';
                            i -= 2;
                            break;
                        case 46:  // SUB
                        //    printf("SUB ");
                            reloc->op = '-';
                            i -= 2;
                            break;
                        case 50:  // DIV
                        //    printf("DIV ");
                            reloc->op = '/';
                            i -= 2;
                            break;
                    }
                }
            //    printf("\n");
                break;
            case 0x3c: // 60 - End SLD info at offset 0
                ptr += 2; // offset
                break;
            case 0xc:  // 12 - XDEF symbol number a 'CRC32_80020BB4' at offset 0 in section 2
            //    printf("XDEF: symbol %x section %d offset %x %.*s\n", *(short*)ptr, *(short*)(ptr+2), *(int*)(ptr+4), *(ptr+8), (ptr+9));
                ptr += 2; // symbol number
                ptr += 2; // section index
                ptr += 4; // offset
            //    printf("XDEF: %.*s\n", *ptr, ptr + 1);
                ptr += *ptr + 1; // symbol name
                break;
            case 0xe:  // 14 - XREF symbol number 24 'GCL_ReadVector_80020A14'
            //    printf("_XREF: symbol %x %.*s\n", *(short*)ptr, *(ptr + 2), (ptr + 3));
                ptr += 2; // symbol number
                ptr += *ptr + 1; // symbol name
                break;
            case 0x52: // 82 - Def
            //    printf("DEF: section %d value %d class %d type %d size %d name %.*s\n", *(short*)ptr, *(int*)(ptr + 2), *(short*)(ptr + 6), *(short*)(ptr + 8), *(short*)(ptr + 10), *(ptr+14), (ptr + 15));
                ptr += 2; // section
                ptr += 4; // value
                ptr += 2; // class
                ptr += 2; // type
                ptr += 4; // size
                ptr += *ptr + 1; // name
                break;
            case 0x54: // 84 - Def2 (arrays)
            //    printf("DEF2: section %d value %d class %d type %d size %d name %.*s\n", *(short*)ptr, *(int*)(ptr + 2), *(short*)(ptr + 6), *(short*)(ptr + 8), *(short*)(ptr + 10), *(ptr + 14), (ptr + 15));
                ptr += 2; // section
                ptr += 4; // value
                ptr += 2; // class
                ptr += 2; // type
                ptr += 4; // size
                dims = *(short*)ptr;
                for (int i = 0; i <= dims; i++)
                {
                    if (i == 0)
                    {
                        ptr += 2; // dims
                    }
                    else
                    {
                        ptr += 4; // dims
                    }
                }
                if (dims && *ptr == 0)
                {
                    ptr += 1; // padding ?
                }
                else
                {
                    ptr += *ptr + 1; // tag (1st line)
                }
                ptr += *ptr + 1; // tag (2nd line)
                break;
            case 0x4a: // 74 - Function start
                ptr += 2; // section
                ptr += 4; // offset
                ptr += 2; // file
                ptr += 4; // start line
                ptr += 2; // frame reg
                ptr += 4; // frame size
                ptr += 2; // return pc reg
                ptr += 4; // mask
                ptr += 4; // mask offset
                printf("function name: %.*s\n", *ptr, ptr + 1);
                ptr += *ptr + 1; // name
                break;
            case 0x4e: // 78 - Block start
                ptr += 2; // section
                ptr += 4; // offset
                ptr += 4; // start line
                break;
            case 0x50: // 80 - Block end
                ptr += 2; // section
                ptr += 4; // offset
                ptr += 4; // end line
                break;
            case 0x4c: // 76 - Function end
                ptr += 2; // section
                ptr += 4; // offset
                ptr += 4; // end line
                break;
            case 0:  // End of file
            //    printf("End of file offset: %d, file size: %d\n", ptr - buffer, file_size);
                if (ptr - buffer != file_size)
                {
                    printf("Error end of file at %x when file size is %x\n", ptr - buffer, file_size);
                    exit(1);
                }
                break;
            default:
                ptr--;
                printf("Error: unknown opcode 0x%x in obj file at offset 0x%x.\n", *ptr, ptr - buffer);
                exit(1);
        }
    }

    return buffer;
}

void removeChar(char* s, char c)
{
    int j, n = strlen(s);

    for (int i = j = 0; i < n; i++)
        if (s[i] != c)
            s[j++] = s[i];
    s[j] = '\0';
}

void usage(void)
{
#ifndef PERMUTER
    printf("usage: MDasm (func.obj / mgs.exe startOffset endOffset) [-o --offsets] [-b --bytes] [-r --reloc] [-c --code]\n");
    printf("    (Optional parameters must be provided at the end).\n");
#endif
    exit(1);
}

int disassemble(BYTE *code, size_t code_size)
{
    csh handle;
    cs_insn* insn;

    if (cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32, &handle) != CS_ERR_OK)
    {
        return -1;
    }

    size_t offset = 0;
    while (code_size > 0)
    {
        size_t count = cs_disasm(handle, (const uint8_t*)code, code_size, offset, 0, &insn);

        code_size -= count * 4;
        code += count * 4;
        offset += count * 4;

        for (size_t j = 0; j < count; j++)
        {
            if (g_params.offsets)
            {
                printf("%4llx:\t", insn[j].address);
            }
            if (g_params.bytes)
            {
                //    for (int i = 0; i < insn[j].size; i++)
                //    {
                //        printf("%X", insn[j].bytes[i]);
                //    }
                //    printf("\t");
                printf("%08X\t", *(int*)insn[j].bytes);
            }
            removeChar(insn[j].op_str, '$');
            bool needReplace = *(int*)&g_relocs[j] /*&& insn[j].mnemonic[0] == 'j' && insn[j].op_str[0] == '0'*/;
            if (needReplace && insn[j].op_str[strlen(insn[j].op_str) - 1] == '0')
            {
                printf("%s\t%.*s%s", insn[j].mnemonic, strlen(insn[j].op_str) - 1, insn[j].op_str, g_relocs[j].expr);
            }
            else
            {
                printf("%s\t%s", insn[j].mnemonic, insn[j].op_str);
                if (needReplace)
                {
                    printf(" <%s>", g_relocs[j].expr);
                }
            }
            //    printf("0x%llx:\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);

            if (*(int*)&g_relocs[j])
            {
                //    if (!needReplace)
                //    {
                //        printf(" <%s>", g_relocs[j].expr);
                //    }
                if (g_params.reloc)
                {
                    printf("\n\t\t\t%x: %s %s", j * 4, g_relocs[j].type, g_relocs[j].name);
                }
            }
            printf("\n");
        }

        cs_free(insn, count);

        if (code_size > 0)
        {
            // cs_disasm did not disassemble the whole function,
            // as there are still some bytes left.
            // Therefore, try to parse the next instruction manually.

            if (g_params.offsets)
            {
                printf("%4llx:\t", offset);
            }

            unsigned int instruction = *(unsigned int*)code;
            unsigned int opcode = (instruction & 0xFE000000) >> 24;

            if (g_params.bytes)
            {
                printf("%08X\t", instruction);
            }

            if (opcode == 0x4A)
            {
                // c2
                printf("c2\t0x%x", instruction & 0x01FFFFFF);
            }
            else
            {
                // unknown
                printf("unk\t0x%x", instruction);
            }

            code_size -= 4;
            code += 4;
            offset += 4;

            printf("\n");
        }
    }

    cs_close(&handle);

    return 0;
}


int main(int argc, char** argv)
{
    BYTE    *buf, *pBuffer;
    int     offsetStart;
    int     offsetEnd;
    int     len;
//    bool    paramOffsets, paramBytes, paramReloc;

    if (argc < 2)
    {
        usage();
    }

 //   paramOffsets = 0;
 //   paramBytes = 0;
 //   paramReloc = 0;
 
#ifndef PERMUTER
    for (int i = 1; i < argc; i++)
    {
        if (!strcmp(argv[i], "--offsets") || !strcmp(argv[i], "-o"))
        //    paramOffsets = 1;
            g_params.offsets = true;
        else if (!strcmp(argv[i], "--bytes") || !strcmp(argv[i], "-b"))
        //    paramBytes = 1;
            g_params.bytes = true;
        else if (!strcmp(argv[i], "--reloc") || !strcmp(argv[i], "-r"))
        //    paramReloc = 1;
            g_params.reloc = true;
        else if (!strcmp(argv[i], "--code") || !strcmp(argv[i], "-c"))
            //    paramReloc = 1;
            g_params.code = true;
        else if (argv[i][0] == '-')
        {
            printf("Error: unknown parameter: %s\n", argv[i]);
            usage();
        }
    }
#else
    g_params.offsets = true;
    g_params.bytes = true;
#endif

    if (*(strrchr(argv[1], '.') + 1) == 'o')
    {
        buf = readPsyqObj(argv[1], &offsetStart, &len);
        pBuffer = buf + offsetStart;
        offsetEnd = len;
    }
    else
    {
        if (argc < 4)
        {
            printf("Error: missing parameters for executable mode.\n");
            usage();
        }

        offsetStart = atoi(argv[2]);
        offsetEnd = atoi(argv[3]);

        if (offsetEnd < offsetStart)
        {
            printf("Offset end must be after the start offset\n");
            return 1;
        }

        const int len = abs(offsetEnd - offsetStart);

        printf("Opening %s offset start = %d offset end = %d\n", argv[1], offsetStart, offsetEnd);
        FILE* file = fopen(argv[1], "rb");
        buf = new BYTE[len];
        pBuffer = buf;
        if (!file)
        {
            printf("Failed to open %s\n", argv[1]);
            return 1;
        }

        if (fseek(file, offsetStart, SEEK_SET))
        {
            printf("seek failed\n");
            return 1;
        }

        const size_t readCount = fread(pBuffer, 1, len, file);
        if (readCount != len)
        {
            printf("Attempted to read %d bytes but got %d bytes\n", len, readCount);
            fclose(file);
            return 1;
        }

        fclose(file);
    }

    for (int i = 0; i < g_totalCodes; i++)
    {
        printf("------------------------------\n");
        disassemble((BYTE*)g_codes[i]->code, g_codes[i]->size);
    }
//    disassemble(pBuffer, offsetEnd);


    delete buf;

    return 0;
}
