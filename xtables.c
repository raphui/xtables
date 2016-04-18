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

#include "mmu.h"

#define NUM_ENTRIES	512
#define TLB_TABLE_SIZE  0x1000

#define START_RANGE	0x400000000
#define END_RANGE	0x500000000

#define BLOCK_SHIFT_L0	39
#define BLOCK_SHIFT_L1	30
#define BLOCK_SHIFT_L2	21

#define BLOCK_SIZE_L0	0x8000000000
#define BLOCK_SIZE_L1   0x40000000
#define BLOCK_SIZE_L2   0x200000

static uint64_t *pgd;
static uint64_t *pmd;
static uint64_t *pte;

void xtables_set_section(uint64_t *pt, int index, uint64_t section, uint64_t memory_type, uint64_t share)
{
        uint64_t val;

        val = section | PMD_TYPE_SECT | PMD_SECT_AF;
        val |= PMD_ATTRINDX(memory_type);
        val |= share;
        pt[index] = val;
}

void xtables_set_table(uint64_t *pt, int index, uint64_t *table_addr)
{
	uint64_t val;

	val = (uint64_t)table_addr | PMD_TYPE_TABLE;
	pt[index] = val;
}

uint64_t xtables_find_table(uint64_t *pgd, uint64_t virt, uint64_t phys, uint64_t size)
{
	uint64_t table = -EINVAL;
	uint64_t table_base = 0;
	int level = 0;


	return table;
}

int xtables_init(int size)
{
	int i;

	pgd = malloc(TLB_TABLE_SIZE);
	if (!pgd) {
		printf("cannot allocate pgd\n");
		return -ENOMEM;
	}

	pmd = malloc(TLB_TABLE_SIZE);
	if (!pmd) {
		printf("cannot allocate pmd\n");
		return -ENOMEM;
	}

	pte = malloc(TLB_TABLE_SIZE);
	if (!pte) {
		printf("cannot allocate pte\n");
		return -ENOMEM;
	}

	memset(pgd, 0, TLB_TABLE_SIZE);
	memset(pmd, 0, TLB_TABLE_SIZE);
	memset(pte, 0, TLB_TABLE_SIZE);

	xtables_set_table(pgd, 0, pmd);
	xtables_set_table(pmd, 0, pte);

	return 0;
}

int main(int argc, char **argv)
{
	int ret = 0;

	ret = xtables_init(END_RANGE - START_RANGE);
	if (ret < 0)
		return ret;

	return ret;
}
