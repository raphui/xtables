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
#define TLB_TABLE_SIZE  0x00004000

#define TEST_START_RANGE	(uint64_t)0x400000000
#define TEST_VIRT_START_RANGE	(uint64_t)0xC00000000
#define TEST_END_RANGE		(uint64_t)0x600444000
#define TEST_ATTR		MEMORY_ATTRIBUTES(MT_NORMAL)
#define TEST_SIZE		(uint64_t)(TEST_END_RANGE - TEST_START_RANGE)

#define IS_ALIGNED(x,a)         (((x) & ((__typeof__(x))(a)-1UL)) == 0)

static uint64_t *pgd;
static int free_idx;	

static int level2shift(int level)
{
	/* Page is 12 bits wide, every level translates 9 bits */
	return (12 + 9 * (3 - level));
}

static uint64_t level2mask(int level)
{
	uint64_t mask = -EINVAL;

	if (level == 1)
		mask = L1_ADDR_MASK;
	else if (level == 2)
		mask = L2_ADDR_MASK;
	else if (level == 3)
		mask = L3_ADDR_MASK;

	return mask;
}

static int pte_type(uint64_t *pte)
{
	return *pte & PMD_TYPE_MASK;
}

static void xtables_set_table(uint64_t *pt, uint64_t *table_addr)
{
	uint64_t val;

	val = PMD_TYPE_TABLE | (uint64_t)table_addr;
	*pt = val;
}

static uint64_t *xtables_create_table(void)
{
	uint64_t *new_table = pgd + free_idx * GRANULE_SIZE;

	/* Mark all entries as invalid */
	memset(new_table, 0, GRANULE_SIZE);

	free_idx++;

	return new_table;
}

static uint64_t *xtables_get_level_table(uint64_t *pte)
{
	uint64_t *table = (uint64_t *)(*pte & XLAT_ADDR_MASK);

	if (pte_type(pte) != PMD_TYPE_TABLE) {
		table = xtables_create_table();
		xtables_set_table(pte, table);
	}

	return table;
}

static uint64_t *xtables_find_entry(uint64_t addr)
{
	uint64_t *pte;
	uint64_t block_shift;
	uint64_t idx;
	int i;

	pte = pgd;

	for (i = 1; i < 4; i++) {
		block_shift = level2shift(i);
		idx = (addr & level2mask(i)) >> block_shift;
		pte += idx;

		if ((pte_type(pte) != PMD_TYPE_TABLE) || (block_shift <= GRANULE_SIZE_SHIFT))
			break;
		else
			pte = (uint64_t *)(*pte & XLAT_ADDR_MASK);
	}

	printf("for %lx got pte at %p [%lx] at level %d with idx %lx\n", addr, pte, *pte, i, idx);

	return pte;
}

static void xtables_map_region(uint64_t virt, uint64_t phys, uint64_t size, uint64_t attr)
{
	uint64_t block_size;
	uint64_t block_shift;
	uint64_t *pte;
	uint64_t idx;
	uint64_t addr;
	uint64_t *table;
	int level;

	addr = virt;

	attr &= ~(PMD_TYPE_SECT);

	while (size) {
		table = pgd;
		for (level = 1; level < 4; level++) {
			block_shift = level2shift(level);
			idx = (addr & level2mask(level)) >> block_shift;
			block_size = (1 << block_shift);

			pte = table + idx;

			if (level == 3)
				attr |= PMD_TYPE_PAGE;
			else
				attr |= PMD_TYPE_SECT;

			if (size >= block_size && IS_ALIGNED(addr, block_size)) {
				*pte = phys | attr;
				printf("map virt [%lx] at phys [%lx] at pte %p [%lx] at level %d\n", addr, phys, pte, *pte, level);
				addr += block_size;
				phys += block_size;
				size -= block_size;
				break;

			}

			table = xtables_get_level_table(pte);
		}

	}
}


static uint64_t xtables_virt_to_phys(uint64_t *pgd, uint64_t virt)
{
	uint64_t phys = virt & 0xFFF;
	uint64_t *entry = (uint64_t *)xtables_find_entry(virt);

	*entry &= 0x7FFFFFF000;

	phys |= *entry;

	return phys;
}

static int xtables_init(void)
{
	uint64_t val;

	pgd = (uint64_t *)malloc(TLB_TABLE_SIZE);
	if (!pgd) {
		printf("cannot allocate pgd\n");
		return -ENOMEM;
	}

	printf("allocate pgd at %p\n", pgd);

	memset(pgd, 0, GRANULE_SIZE);
	free_idx = 1;

	xtables_map_region(TEST_VIRT_START_RANGE, TEST_START_RANGE, TEST_SIZE, PMD_TYPE_SECT | PMD_SECT_AF);

	val = xtables_virt_to_phys(pgd, TEST_VIRT_START_RANGE);

	printf("for virt %lx got phys %lx\n", TEST_VIRT_START_RANGE, val);

	free(pgd);

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	ret = xtables_init();
	if (ret < 0)
		return ret;

	return ret;
}
