#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/wait.h>
#include <fnmatch.h>
#include <sys/mman.h>
#include <stdint.h>
#include <libgen.h>

typedef struct {
    uint32_t lo;
    uint32_t hi;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t buffer[64];
    uint32_t block[16];
} Md5Context;

#define MD5_HASH_SIZE (128 / 8)

typedef struct {
    uint8_t bytes[MD5_HASH_SIZE];
} MD5_HASH;

typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;
typedef uint32_t Elf32_Word;
typedef uint32_t Elf64_Word;
typedef uint64_t Elf64_Xword;
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

#define EI_NIDENT 16

typedef struct elf32_hdr {
    unsigned char e_ident[EI_NIDENT];
    Elf32_Half e_type;
    Elf32_Half e_machine;
    Elf32_Word e_version;
    Elf32_Addr e_entry; /* Entry point */
    Elf32_Off e_phoff;
    Elf32_Off e_shoff;
    Elf32_Word e_flags;
    Elf32_Half e_ehsize;
    Elf32_Half e_phentsize;
    Elf32_Half e_phnum;
    Elf32_Half e_shentsize;
    Elf32_Half e_shnum;
    Elf32_Half e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
    unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry; /* Entry point virtual address */
    Elf64_Off e_phoff; /* Program header table file offset */
    Elf64_Off e_shoff; /* Section header table file offset */
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

typedef struct elf32_shdr {
    Elf32_Word sh_name;
    Elf32_Word sh_type;
    Elf32_Word sh_flags;
    Elf32_Addr sh_addr;
    Elf32_Off sh_offset;
    Elf32_Word sh_size;
    Elf32_Word sh_link;
    Elf32_Word sh_info;
    Elf32_Word sh_addralign;
    Elf32_Word sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
    Elf64_Word sh_name; /* Section name, index in string tbl */
    Elf64_Word sh_type; /* Type of section */
    Elf64_Xword sh_flags; /* Miscellaneous section attributes */
    Elf64_Addr sh_addr; /* Section virtual addr at execution */
    Elf64_Off sh_offset; /* Section file offset */
    Elf64_Xword sh_size; /* Size of section in bytes */
    Elf64_Word sh_link; /* Index of another section */
    Elf64_Word sh_info; /* Additional section information */
    Elf64_Xword sh_addralign; /* Section alignment */
    Elf64_Xword sh_entsize; /* Entry size if section holds table */
} Elf64_Shdr;

/* Note header in a PT_NOTE section */
typedef struct elf32_note {
    Elf32_Word n_namesz; /* Name size */
    Elf32_Word n_descsz; /* Content size */
    Elf32_Word n_type; /* Content type */
} Elf32_Nhdr;

#define ELFCLASS32  1
#define ELFDATA2LSB 1
#define ELFDATA2MSB 2
#define ELFCLASS64  2
#define EI_CLASS    4
#define EI_DATA     5

#define bswap_16(value) \
((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
<< 32) | \
(uint64_t)bswap_32((uint32_t)((value) >> 32)))

typedef Elf32_Nhdr Elf_Nhdr;

static Elf64_Ehdr ehdr;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define ELFDATANATIVE ELFDATA2LSB
#elif __BYTE_ORDER == __BIG_ENDIAN
#define ELFDATANATIVE ELFDATA2MSB
#else
#error "Unknown machine endian"
#endif

static uint16_t file16_to_cpu(uint16_t val) {
    if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
        val = bswap_16(val);
    return val;
}

static uint32_t file32_to_cpu(uint32_t val) {
    if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
        val = bswap_32(val);
    return val;
}

static uint64_t file64_to_cpu(uint64_t val) {
    if (ehdr.e_ident[EI_DATA] != ELFDATANATIVE)
        val = bswap_64(val);
    return val;
}

static off_t read_elf32(FILE* fd) {
    Elf32_Ehdr ehdr32;
    Elf32_Shdr shdr32;
    off_t last_shdr_offset;
    ssize_t ret;
    off_t sht_end, last_section_end;

    fseeko(fd, 0, SEEK_SET);
    ret = fread(&ehdr32, 1, sizeof(ehdr32), fd);
    if (ret < 0 || (size_t) ret != sizeof(ehdr32)) {
        fprintf(stderr, "Read of ELF header failed: %s\n", strerror(errno));
        return -1;
    }

    ehdr.e_shoff = file32_to_cpu(ehdr32.e_shoff);
    ehdr.e_shentsize = file16_to_cpu(ehdr32.e_shentsize);
    ehdr.e_shnum = file16_to_cpu(ehdr32.e_shnum);

    last_shdr_offset = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum - 1));
    fseeko(fd, last_shdr_offset, SEEK_SET);
    ret = fread(&shdr32, 1, sizeof(shdr32), fd);
    if (ret < 0 || (size_t) ret != sizeof(shdr32)) {
        fprintf(stderr, "Read of ELF section header failed: %s\n", strerror(errno));
        return -1;
    }

    /* ELF ends either with the table of section headers (SHT) or with a section. */
    sht_end = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);
    last_section_end = file64_to_cpu(shdr32.sh_offset) + file64_to_cpu(shdr32.sh_size);
    return sht_end > last_section_end ? sht_end : last_section_end;
}

static off_t read_elf64(FILE* fd) {
    Elf64_Ehdr ehdr64;
    Elf64_Shdr shdr64;
    off_t last_shdr_offset;
    off_t ret;
    off_t sht_end, last_section_end;

    fseeko(fd, 0, SEEK_SET);
    ret = fread(&ehdr64, 1, sizeof(ehdr64), fd);
    if (ret < 0 || (size_t) ret != sizeof(ehdr64)) {
        fprintf(stderr, "Read of ELF header failed: %s\n", strerror(errno));
        return -1;
    }

    ehdr.e_shoff = file64_to_cpu(ehdr64.e_shoff);
    ehdr.e_shentsize = file16_to_cpu(ehdr64.e_shentsize);
    ehdr.e_shnum = file16_to_cpu(ehdr64.e_shnum);

    last_shdr_offset = ehdr.e_shoff + (ehdr.e_shentsize * (ehdr.e_shnum - 1));
    fseeko(fd, last_shdr_offset, SEEK_SET);
    ret = fread(&shdr64, 1, sizeof(shdr64), fd);
    if (ret < 0 || ret != sizeof(shdr64)) {
        fprintf(stderr, "Read of ELF section header failed: %s\n", strerror(errno));
        return -1;
    }

    /* ELF ends either with the table of section headers (SHT) or with a section. */
    sht_end = ehdr.e_shoff + (ehdr.e_shentsize * ehdr.e_shnum);
    last_section_end = file64_to_cpu(shdr64.sh_offset) + file64_to_cpu(shdr64.sh_size);
    return sht_end > last_section_end ? sht_end : last_section_end;
}

ssize_t appimage_get_elf_size(const char* fname) {
    off_t ret;
    FILE* fd = NULL;
    off_t size = -1;

    fd = fopen(fname, "rb");
    if (fd == NULL) {
        fprintf(stderr, "Cannot open %s: %s\n",
                fname, strerror(errno));
        return -1;
    }
    ret = fread(ehdr.e_ident, 1, EI_NIDENT, fd);
    if (ret != EI_NIDENT) {
        fprintf(stderr, "Read of e_ident from %s failed: %s\n", fname, strerror(errno));
        return -1;
    }
    if ((ehdr.e_ident[EI_DATA] != ELFDATA2LSB) &&
        (ehdr.e_ident[EI_DATA] != ELFDATA2MSB)) {
        fprintf(stderr, "Unknown ELF data order %u\n",
                ehdr.e_ident[EI_DATA]);
        return -1;
    }
    if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
        size = read_elf32(fd);
    } else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
        size = read_elf64(fd);
    } else {
        fprintf(stderr, "Unknown ELF class %u\n", ehdr.e_ident[EI_CLASS]);
        return -1;
    }

    fclose(fd);
    return size;
}

/* Return the offset, and the length of an ELF section with a given name in a given ELF file */
bool appimage_get_elf_section_offset_and_length(const char* fname, const char* section_name, unsigned long* offset, unsigned long* length) {
        uint8_t* data;
        int i;
        int fd = open(fname, O_RDONLY);
        size_t map_size = (size_t) lseek(fd, 0, SEEK_END);

        data = mmap(NULL, map_size, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);

        // this trick works as both 32 and 64 bit ELF files start with the e_ident[EI_NINDENT] section
        unsigned char class = data[EI_CLASS];

        if (class == ELFCLASS32) {
                Elf32_Ehdr* elf;
                Elf32_Shdr* shdr;

                elf = (Elf32_Ehdr*) data;
                shdr = (Elf32_Shdr*) (data + ((Elf32_Ehdr*) elf)->e_shoff);

                char* strTab = (char*) (data + shdr[elf->e_shstrndx].sh_offset);
                for (i = 0; i < elf->e_shnum; i++) {
                        if (strcmp(&strTab[shdr[i].sh_name], section_name) == 0) {
                                *offset = shdr[i].sh_offset;
                                *length = shdr[i].sh_size;
                        }
                }
        } else if (class == ELFCLASS64) {
                Elf64_Ehdr* elf;
                Elf64_Shdr* shdr;

                elf = (Elf64_Ehdr*) data;
                shdr = (Elf64_Shdr*) (data + elf->e_shoff);

                char* strTab = (char*) (data + shdr[elf->e_shstrndx].sh_offset);
                for (i = 0; i < elf->e_shnum; i++) {
                        if (strcmp(&strTab[shdr[i].sh_name], section_name) == 0) {
                                *offset = shdr[i].sh_offset;
                                *length = shdr[i].sh_size;
                        }
                }
        } else {
                fprintf(stderr, "Platforms other than 32-bit/64-bit are currently not supported!");
                munmap(data, map_size);
                return false;
        }

        munmap(data, map_size);
        return true;
}

/* Return the offset, and the length of an ELF section with a given name in a given ELF file */
char* read_file_offset_length(const char* fname, unsigned long offset, unsigned long length) {
    FILE* f;
    if ((f = fopen(fname, "r")) == NULL) {
        return NULL;
    }

    fseek(f, offset, SEEK_SET);

    char* buffer = calloc(length + 1, sizeof(char));
    fread(buffer, length, sizeof(char), f);

    fclose(f);

    return buffer;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return 1;
    }

    const char* fname = argv[1];
    ssize_t size = appimage_get_elf_size(fname);

    if (size == -1) {
        fprintf(stderr, "Error: unable to get ELF size for file '%s'\n", fname);
        return 1;
    }

    printf("%lld\n", (long long)size);

    return 0;
}
