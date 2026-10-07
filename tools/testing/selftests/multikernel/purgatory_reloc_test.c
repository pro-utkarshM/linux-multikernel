// SPDX-License-Identifier: GPL-2.0-only
/* Actual C handler, synthetic valid ELF layout; no kernel/firmware execution. */
#include <elf.h>
#include <endian.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Sym Elf_Sym;
struct purgatory_info {
	Elf64_Ehdr *ehdr;
	Elf_Shdr *sechdrs;
	void *purgatory_buf;
};

#define RV_X(x, s, n) (((x) >> (s)) & ((1 << (n)) - 1))
#define pr_err(...) fprintf(stderr, __VA_ARGS__)

static u32 get_unaligned_le32(const void *p)
{
	u32 value;

	memcpy(&value, p, sizeof(value));
	return le32toh(value);
}

static void put_unaligned_le32(u32 value, void *p)
{
	value = htole32(value);
	memcpy(p, &value, sizeof(value));
}

#include "reloc-production.h"

_Static_assert(sizeof(unsigned long) == 8, "requires a 64-bit host");

enum { TEXT = 1, DATA, SYMTAB, STRTAB, NSECTIONS };
#define TEXT_ADDR 0x1000000000UL
struct fixture {
	struct {
		Elf64_Ehdr ehdr;
		Elf_Shdr sections[NSECTIONS];
		Elf_Sym symbols[8];
		Elf64_Rela relas[8];
		char strings[16];
	} elf;
	Elf_Shdr loaded[NSECTIONS], relsec;
	struct purgatory_info pi;
	u64 output[12];
};

static unsigned int checks, failures;

static void expect(const char *name, bool ok)
{
	checks++;
	if (!ok) {
		fprintf(stderr, "FAIL: %s\n", name);
		failures++;
	}
}

static void word(struct fixture *f, unsigned int off, u32 insn)
{
	put_unaligned_le32(insn, (char *)f->output + 8 + off);
}

static u32 read_word(struct fixture *f, unsigned int off)
{
	return get_unaligned_le32((char *)f->output + 8 + off);
}

static void init(struct fixture *f)
{
	memset(f, 0, sizeof(*f));
	f->elf.ehdr.e_shoff = offsetof(struct fixture, elf.sections);
	f->elf.ehdr.e_shnum = NSECTIONS;
	f->elf.ehdr.e_shstrndx = STRTAB;
	f->elf.sections[STRTAB].sh_offset = offsetof(struct fixture, elf.strings);
	f->elf.sections[SYMTAB].sh_offset = offsetof(struct fixture, elf.symbols);
	f->elf.sections[SYMTAB].sh_size = sizeof(f->elf.symbols);
	f->elf.sections[SYMTAB].sh_link = STRTAB;
	f->loaded[TEXT].sh_addr = TEXT_ADDR;
	f->loaded[TEXT].sh_offset = 8;
	f->loaded[TEXT].sh_size = 64;
	f->loaded[DATA].sh_addr = TEXT_ADDR + 0x2345;
	f->elf.symbols[1] = (Elf_Sym){ .st_name = 1, .st_shndx = DATA };
	f->elf.symbols[2] = (Elf_Sym){ .st_name = 1, .st_shndx = TEXT };
	f->relsec.sh_offset = offsetof(struct fixture, elf.relas);
	f->relsec.sh_info = TEXT;
	f->pi = (struct purgatory_info){ &f->elf.ehdr, f->loaded, f->output };
	memset(f->output, 0xa5, sizeof(f->output));
}

static void rela(struct fixture *f, unsigned int off, unsigned int type,
		 unsigned int sym, long addend)
{
	unsigned int n = f->relsec.sh_size / sizeof(Elf64_Rela);

	f->elf.relas[n] = (Elf64_Rela){ off, ELF64_R_INFO(sym, type), addend };
	f->relsec.sh_size += sizeof(Elf64_Rela);
}

static int apply(struct fixture *f)
{
	return arch_kexec_apply_relocations_add(&f->pi, &f->loaded[TEXT],
					       &f->relsec, &f->elf.sections[SYMTAB]);
}

static void pair(struct fixture *f, unsigned int hi, unsigned int lo)
{
	word(f, hi, 0x00000517); /* auipc a0, 0 */
	word(f, lo, 0x00050513); /* addi a0, a0, 0 */
	f->elf.symbols[2].st_value = hi;
	rela(f, hi, R_RISCV_PCREL_HI20, 1, 0);
	rela(f, lo, R_RISCV_PCREL_LO12_I, 2, 0);
}

int main(void)
{
	struct fixture f;
	Elf64_Rela swap;
	static const struct {
		long offset;
		u32 high, low;
	} limits[] = {
		{ 0, 0, 0 }, { 0x7ff, 0, 0x7ff }, { 0x800, 0x1000, 0x800 },
		{ -0x800, 0, 0x800 }, { -0x801, 0xfffff000, 0x7ff },
		{ 0x7ffff7ff, 0x7ffff000, 0x7ff },
		{ -0x80000800L, 0x80000000, 0x800 },
	};

	init(&f);
	pair(&f, 0, 4);
	expect("adjacent pair", !apply(&f) && read_word(&f, 0) == 0x00002517 &&
	       read_word(&f, 4) == 0x34550513 && read_word(&f, 8) == 0xa5a5a5a5);

	init(&f);
	pair(&f, 0, 12);
	f.elf.symbols[3] = (Elf_Sym){ .st_name = 1, .st_shndx = DATA, .st_value = 0x3337 };
	f.elf.symbols[4] = (Elf_Sym){ .st_name = 1, .st_shndx = TEXT, .st_value = 4 };
	word(&f, 4, 0x00000597); /* auipc a1, 0 */
	word(&f, 8, 0x00058593); /* addi a1, a1, 0 */
	rela(&f, 4, R_RISCV_PCREL_HI20, 3, 0);
	rela(&f, 8, R_RISCV_PCREL_LO12_I, 4, 0);
	expect("interleaved independent pairs", !apply(&f) &&
	       read_word(&f, 0) == 0x00002517 && read_word(&f, 4) == 0x00005597 &&
	       read_word(&f, 8) == 0x67858593 && read_word(&f, 12) == 0x34550513);

	init(&f);
	pair(&f, 2, 10); /* RV64C permits instructions at two-byte alignment. */
	f.elf.relas[0].r_addend = 2; /* target displacement stays 0x2345 */
	swap = f.elf.relas[0];
	f.elf.relas[0] = f.elf.relas[1];
	f.elf.relas[1] = swap;
	expect("LO before HI, addend, halfword alignment", !apply(&f) &&
	       read_word(&f, 2) == 0x00002517 && read_word(&f, 10) == 0x34550513);
	expect("intervening instruction bytes preserved", read_word(&f, 6) == 0xa5a5a5a5);

	init(&f);
	pair(&f, 0, 8);
	word(&f, 16, 0x00b53023); /* sd a1, 0(a0) */
	rela(&f, 16, R_RISCV_PCREL_LO12_S, 2, 0);
	expect("multiple low users including S-type", !apply(&f) &&
	       read_word(&f, 8) == 0x34550513 && read_word(&f, 16) == 0x34b532a3);
	expect("prefix and intervening bytes preserved", f.output[0] == 0xa5a5a5a5a5a5a5a5ULL &&
	       read_word(&f, 4) == 0xa5a5a5a5 && read_word(&f, 12) == 0xa5a5a5a5 &&
	       read_word(&f, 20) == 0xa5a5a5a5);
	init(&f);
	pair(&f, 0, 8);
	word(&f, 0, 0xfffff517);
	word(&f, 8, 0xfff50513);
	word(&f, 16, 0xfeb53fa3);
	rela(&f, 16, R_RISCV_PCREL_LO12_S, 2, 0);
	expect("HI/I/S immediates replaced, not ORed", !apply(&f) &&
	       read_word(&f, 0) == 0x00002517 && read_word(&f, 8) == 0x34550513 &&
	       read_word(&f, 16) == 0x34b532a3);
	init(&f);
	word(&f, 0, 0x00000517);
	word(&f, 8, 0x00b53023);
	f.loaded[DATA].sh_addr = TEXT_ADDR - 0x800;
	rela(&f, 0, R_RISCV_PCREL_HI20, 1, 0);
	rela(&f, 8, R_RISCV_PCREL_LO12_S, 2, 0);
	expect("negative S-type immediate", !apply(&f) && read_word(&f, 8) == 0x80b53023);

	init(&f);
	pair(&f, 0, 8);
	f.elf.relas[0].r_addend = -0x4000;
	expect("negative HI addend", !apply(&f) && read_word(&f, 0) == 0xffffe517 &&
	       read_word(&f, 8) == 0x34550513);

	for (unsigned int i = 0; i < sizeof(limits) / sizeof(limits[0]); i++) {
		init(&f);
		pair(&f, 0, 8);
		f.elf.symbols[1].st_shndx = SHN_ABS;
		f.elf.symbols[1].st_value = TEXT_ADDR + limits[i].offset;
		expect("signed displacement and rounding boundary", !apply(&f) &&
		       read_word(&f, 0) == (limits[i].high | 0x517) &&
		       read_word(&f, 8) == ((limits[i].low << 20) | 0x50513));
	}
	for (unsigned int i = 0; i < 2; i++) {
		init(&f);
		pair(&f, 0, 8);
		f.loaded[DATA].sh_addr = TEXT_ADDR + (i ? -0x80000801L : 0x7ffff800L);
		expect("out-of-range HI rejected", apply(&f) == -ENOEXEC);
	}
	for (unsigned int i = 0; i < 3; i++) {
		init(&f);
		pair(&f, 0, 8);
		if (i == 0)
			f.elf.symbols[2].st_value = 4; /* No HI at this label. */
		else if (i == 1)
			f.elf.symbols[2].st_shndx = DATA; /* Same offset, wrong section. */
		else
			f.elf.relas[0].r_info = ELF64_R_INFO(1, R_RISCV_RELAX);
		expect("missing or wrong HI match rejected", apply(&f) == -ENOEXEC);
	}
	init(&f);
	pair(&f, 0, 8);
	f.elf.relas[1].r_addend = 1;
	expect("nonzero LO addend rejected", apply(&f) == -ENOEXEC);
	init(&f);
	pair(&f, 0, 8);
	f.elf.symbols[1].st_shndx = SHN_COMMON;
	swap = f.elf.relas[0];
	f.elf.relas[0] = f.elf.relas[1];
	f.elf.relas[1] = swap;
	expect("LO-first invalid target section rejected", apply(&f) == -ENOEXEC);
	init(&f);
	word(&f, 0, 0x00000097);
	word(&f, 4, 0x000080e7);
	rela(&f, 0, R_RISCV_CALL_PLT, 1, 0);
	expect("CALL_PLT still patches its adjacent pair", !apply(&f) &&
	       read_word(&f, 0) == 0x00002097 && read_word(&f, 4) == 0x345080e7);
	printf("purgatory relocations: %u checks, %u failures\n", checks, failures);
	return failures != 0;
}
