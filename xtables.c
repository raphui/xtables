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
#define TEST_START_RANGE	0x000000000
#define TEST_END_RANGE		0x100444000
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

#define VA_START                   0x0
#define BITS_PER_VA                33
/* Granule size of 4KB is being used */
#define GRANULE_SIZE_SHIFT         12
#define GRANULE_SIZE               (1 << GRANULE_SIZE_SHIFT)
#define XLAT_ADDR_MASK             ((1UL << BITS_PER_VA) - GRANULE_SIZE)
#define GRANULE_SIZE_MASK          ((1 << GRANULE_SIZE_SHIFT) - 1)

#define BITS_RESOLVED_PER_LVL   (GRANULE_SIZE_SHIFT - 3)
#define L1_ADDR_SHIFT           (GRANULE_SIZE_SHIFT + BITS_RESOLVED_PER_LVL * 2)
#define L2_ADDR_SHIFT           (GRANULE_SIZE_SHIFT + BITS_RESOLVED_PER_LVL * 1)
#define L3_ADDR_SHIFT           (GRANULE_SIZE_SHIFT + BITS_RESOLVED_PER_LVL * 0)


#define L1_ADDR_MASK     (((1UL << BITS_RESOLVED_PER_LVL) - 1) << L1_ADDR_SHIFT)
#define L2_ADDR_MASK     (((1UL << BITS_RESOLVED_PER_LVL) - 1) << L2_ADDR_SHIFT)
#define L3_ADDR_MASK     (((1UL << BITS_RESOLVED_PER_LVL) - 1) << L3_ADDR_SHIFT)

/* These macros give the size of the region addressed by each entry of a xlat
   table at any given level */
#define L3_XLAT_SIZE               (1UL << L3_ADDR_SHIFT)
#define L2_XLAT_SIZE               (1UL << L2_ADDR_SHIFT)
#define L1_XLAT_SIZE               (1UL << L1_ADDR_SHIFT)

#define IS_ALIGNED(x,a)         (((x) & ((__typeof__(x))(a)-1UL)) == 0)

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

static uint64_t level2mask(int level)
{
	if (level == 1)
		return L1_ADDR_MASK;
	else if (level == 2)
		return L2_ADDR_MASK;
	else if (level == 3)
		return L3_ADDR_MASK;
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

	val = PMD_TYPE_TABLE | (uint64_t)table_addr;
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

static uint64_t *xtables_find_entry(uint64_t *pgd, uint64_t addr)
{
	uint64_t *entry = pgd;
	uint64_t block_shift;
	int i;
	int idx;

	for (i = 1; i < 4; i++) {
		block_shift = level2shift(i);
		idx = (addr >> block_shift) & 0x1FF;
		entry += idx;

		printf("idx=%llx PTE %p at level %d: %llx\n", idx, entry, i, *entry);

		if ((entry_type(entry) != PMD_TYPE_TABLE) || (block_shift <= GRANULE_SIZE_SHIFT))
			break;
		else
			entry = (uint64_t *)(*entry & XLAT_ADDR_MASK);	
	}


	return entry;
}

static void xtables_map_region(uint64_t *pgd, uint64_t base, uint64_t size, uint64_t attr)
{
	uint64_t block_size;
	uint64_t block_shift;
	uint64_t *entry;
	uint64_t idx;
	uint64_t *table;
	int level;

	table = pgd;

	while (size) {
		for (level = 1; level < 4; level++) {
			idx = (base & level2mask(level)) >> level2shift(level);
			block_size = (1 << level2shift(level));

			if (size >= block_size && IS_ALIGNED(base, block_size)) {
				entry = table + idx;
				if (level == 3)
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
	uint64_t entry = xtables_find_entry(pgd, virt);

	entry &= 0x7FFFFFF000;
//	entry << 11;

	phys |= entry;

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

	xtables_map_region(pgd, TEST_START_RANGE, TEST_SIZE, PMD_TYPE_SECT | PMD_SECT_AF);


	printf("virt: %llx, phys: %llx\n", virt, xtables_virt_to_phys(pgd, virt));

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
