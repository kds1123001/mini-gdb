#include "elf_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

static void collect_symtab(elf_image_t *img, Elf64_Shdr *symtab_shdr, Elf64_Shdr *strtab_shdr) {
    Elf64_Sym *syms = (Elf64_Sym *)((char *)img->map + symtab_shdr->sh_offset);
    size_t n = symtab_shdr->sh_size / sizeof(Elf64_Sym);
    char *strtab = (char *)img->map + strtab_shdr->sh_offset;

    size_t old_count = img->sym_count;
    elf_sym_t *grown = realloc(img->syms, (old_count + n) * sizeof(elf_sym_t));
    if (!grown) return;
    img->syms = grown;

    size_t added = 0;
    for (size_t i = 0; i < n; i++) {
        if (syms[i].st_name == 0) continue;
        const char *nm = strtab + syms[i].st_name;
        if (!*nm) continue;
        img->syms[old_count + added].name = strdup(nm);
        img->syms[old_count + added].addr = syms[i].st_value;
        img->syms[old_count + added].size = syms[i].st_size;
        img->syms[old_count + added].info = syms[i].st_info;
        added++;
    }
    img->sym_count = old_count + added;
}

int elf_load(const char *path, elf_image_t *img) {
    memset(img, 0, sizeof(*img));
    img->fd = open(path, O_RDONLY);
    if (img->fd < 0) return -1;

    struct stat st;
    if (fstat(img->fd, &st) < 0) { close(img->fd); return -1; }
    img->map_size = st.st_size;
    img->map = mmap(NULL, img->map_size, PROT_READ, MAP_PRIVATE, img->fd, 0);
    if (img->map == MAP_FAILED) { close(img->fd); return -1; }

    img->ehdr = (Elf64_Ehdr *)img->map;
    if (memcmp(img->ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        elf_unload(img);
        return -1;
    }
    if (img->ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        elf_unload(img);
        return -1;
    }

    img->is_pie = (img->ehdr->e_type == ET_DYN);
    img->shdrs = (Elf64_Shdr *)((char *)img->map + img->ehdr->e_shoff);

    Elf64_Shdr *shstrtab = &img->shdrs[img->ehdr->e_shstrndx];
    char *shstr = (char *)img->map + shstrtab->sh_offset;

    for (int i = 0; i < img->ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &img->shdrs[i];
        if (sh->sh_type == SHT_SYMTAB || sh->sh_type == SHT_DYNSYM) {
            Elf64_Shdr *strtab_sh = &img->shdrs[sh->sh_link];
            collect_symtab(img, sh, strtab_sh);
        }
        (void)shstr;
    }
    return 0;
}

void elf_unload(elf_image_t *img) {
    for (size_t i = 0; i < img->sym_count; i++) free(img->syms[i].name);
    free(img->syms);
    if (img->map && img->map != MAP_FAILED) munmap(img->map, img->map_size);
    if (img->fd >= 0) close(img->fd);
    memset(img, 0, sizeof(*img));
}

int elf_resolve_symbol(elf_image_t *img, const char *name, uint64_t *addr_out) {
    for (size_t i = 0; i < img->sym_count; i++) {
        if (strcmp(img->syms[i].name, name) == 0) {
            *addr_out = img->syms[i].addr;
            return 0;
        }
    }
    return -1;
}

void elf_list_symbols(elf_image_t *img) {
    for (size_t i = 0; i < img->sym_count; i++) {
        int type = ELF64_ST_TYPE(img->syms[i].info);
        if (type != STT_FUNC) continue;
        if (img->syms[i].addr == 0) continue;
        printf("%016lx  %6lu  %s\n", img->syms[i].addr, img->syms[i].size, img->syms[i].name);
    }
}

uint64_t elf_entry_point(elf_image_t *img) {
    return img->ehdr->e_entry;
}
