#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <elf.h>

typedef struct {
    char *name;
    uint64_t addr;
    uint64_t size;
    unsigned char info;
} elf_sym_t;

typedef struct {
    int fd;
    void *map;
    size_t map_size;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdrs;
    int is_pie;
    elf_sym_t *syms;
    size_t sym_count;
} elf_image_t;

int elf_load(const char *path, elf_image_t *img);
void elf_unload(elf_image_t *img);
int elf_resolve_symbol(elf_image_t *img, const char *name, uint64_t *addr_out);
void elf_list_symbols(elf_image_t *img);
uint64_t elf_entry_point(elf_image_t *img);

#endif
