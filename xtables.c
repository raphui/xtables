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

#define NUM_ENTRIES	512
#define TLB_TABLE_SIZE  0x1000

#define START_RANGE	0x400000000
#define END_RANGE	0x500000000

#define L0_SHIFT	39
#define L1_SHIFT	30
#define L2_SHIFT	21

static uint64_t *pgd;
static uint64_t *pmd;
static uint64_t *pte;

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
