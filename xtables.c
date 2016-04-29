/*
 * Copyright (C) 2016  Raphaël Poggi <poggi.raph@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <linux/types.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "mmu.h"

#define MAX_ENTRIES	512
#define TLB_TABLE_SIZE  0x40000000

#define TEST_FILENAME		"va_mem"
#define TEST_START_RANGE	0x400000000
#define TEST_END_RANGE		0x500000000
#define TEST_ATTR		MEMORY_ATTRIBUTES(MT_NORMAL)
#define TEST_SIZE		TEST_END_RANGE - TEST_START_RANGE

#define BLOCK_SHIFT_L0	39
#define BLOCK_SHIFT_L1	30
#define BLOCK_SHIFT_L2	21
#define BLOCK_SHIFT_L3	12

#define BLOCK_SIZE_L0	0x8000000000
#define BLOCK_SIZE_L1   0x40000000
#define BLOCK_SIZE_L2   0x200000
#define BLOCK_SIZE_L3   0x1000

static uint64_t *pgd;
static uint64_t *pmd;
static uint64_t *pte;

static uint64_t virt;

static int fd;

static int level2shift(int level)
{
	/* Page is 12 bits wide, every level translates 9 bits */
	return (12 + 9 * (3 - level));
}

static int entry_type(uint64_t *entry)
{
	return *entry & PMD_TYPE_MASK;
}

static void xtables_set_section(uint64_t *pt, uint64_t section, uint64_t memory_type, uint64_t share)
{
        uint64_t val;

        val = section | PMD_TYPE_SECT | PMD_SECT_AF;
        val |= PMD_ATTRINDX(memory_type);
        val |= share;
        pt = val;
}

static void xtables_set_table(uint64_t *pt, uint64_t *table_addr)
{
	uint64_t val;

	val = (uint64_t)table_addr | PMD_TYPE_TABLE;
	*pt = val;
}

static uint64_t *xtables_create_table(uint64_t *pgd)
{
	uint64_t *new_table = pgd;
	uint64_t pt_len = MAX_ENTRIES * sizeof(uint64_t);

	/* Allocate MAX_ENTRIES pte entries */
	pgd += pt_len;

	/* Mark all entries as invalid */
	memset(new_table, 0, pt_len);

	return new_table;
}

static uint64_t *xtables_find_entry(uint64_t *pgd, uint64_t addr, int level)
{
	uint64_t *entry = pgd;
	uint64_t block_shift;
	int i;

	for (i = 0; i < 4; i++) {
		block_shift = level2shift(i);
		entry += (addr >> block_shift) & 0x1FF;

		if (i == level)
			break;

		if (entry_type(entry) & PMD_TYPE_FAULT) {
			entry = NULL;
			break;
		}
		else
			entry = (uint64_t *)(*entry & 0x0000fffffffff000ULL);	
	}


	return entry;
}

static void xtables_map_region(uint64_t *pgd, uint64_t base, uint64_t size, uint64_t attr)
{
	uint64_t block_size;
	uint64_t *entry;
	uint64_t *table;
	int level;

	while (size) {
		entry = xtables_find_entry(pgd, base, 0);
		if (entry && (entry_type(entry) == PMD_TYPE_FAULT)) {
			table = xtables_create_table(pgd);
			xtables_set_table(entry, table);
		}

		for (level = 1; level < 4; level++) {
			entry = xtables_find_entry(pgd, base, level);
			block_size = (1 << level2shift(level));

			if (size >= block_size && !(base & (block_size - 1))) {
				printf("entry: %x\n", entry);
				virt = entry;
				*entry = base | attr;
				base += block_size;
				size -= block_size;
				break;

			} else if (entry_type(entry) == PMD_TYPE_FAULT) {
				table = xtables_create_table(pgd);
				xtables_set_table(entry, table);
			}
		}

	}
}

static uint64_t xtables_virt_to_phys(uint64_t *pgd, uint64_t virt)
{
	uint64_t phys = virt & 0xFFF;
	uint64_t entry_lvl3 = xtables_find_entry(pgd, virt, 3);

	entry_lvl3 << 11;

	phys |= entry_lvl3;

	return phys;
}

static int xtables_init(int size)
{
	int i;

	pgd = mmap(NULL, TLB_TABLE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (pgd < 0) {
		printf("cannot allocate pgd\n");
		return -ENOMEM;
	}

	pgd = xtables_create_table(pgd);

	xtables_map_region(pgd, TEST_START_RANGE, TEST_SIZE, 0);


	printf("virt: %x, phys: %x\n", virt, xtables_virt_to_phys(pgd, virt));

	munmap(pgd, TLB_TABLE_SIZE);

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	fd = open(TEST_FILENAME, O_RDWR);
	if (fd < 0)
		return ret;

	ret = xtables_init(TEST_SIZE);
	if (ret < 0)
		return ret;


	close(fd);

	return ret;
}
