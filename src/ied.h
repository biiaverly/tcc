/**
 * Rapid-prototyping protection schemes with IEC 61850
 *
 * Copyright (c) 2014 Steven Blair
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef IED_H
#define IED_H

#ifdef __cplusplus /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#include "datatypes.h"
#include "sv.h"
#include "gse.h"


struct E1Q1SB1_t {
	struct {
		struct {
			struct {
				struct LN0 LLN0;
				struct svControl PerformanceSV;
				struct gseControl Performance;
				struct gseControl ItlPositions;
				struct gseControl AnotherPositions;
				struct svControl Volt;
				struct svControl rmxuCB;
			} LN0;
			struct exampleRMXU exampleRMXU_1;
			struct LPHDa LPHDa_1;
			struct CSWIa CSWIa_1;
			struct CSWIa CSWIa_2;
			struct MMXUa MMXUa_1;
			struct TVTRa TVTRa_1;
		} C1;
	} S1;
};

struct E1Q1BP2_t {
	struct {
	} S1;
};

struct E1Q1BP3_t {
	struct {
	} S1;
};

struct E1Q2SB1_t {
	struct {
	} S1;
};

struct E1Q3SB1_t {
	struct {
	} S1;
};

struct E1Q3KA1_t {
	struct {
	} S1;
};

struct E1Q3KA2_t {
	struct {
	} S1;
};

struct E1Q3KA3_t {
	struct {
	} S1;
};

struct D1Q1SB1_t {
	struct {
	} S1;
};

struct D1Q1BP2_t {
	struct {
	} S1;
};

struct D1Q1BP3_t {
	struct {
	} S1;
};

struct D1Q1SB4_t {
	struct {
		struct {
			struct {
				struct LN0 LLN0;
				struct gseControl SyckResult;
				struct gseControl MMXUResult;
			} LN0;
			struct exampleMMXU exampleMMXU_1;
			struct LPHDa LPHDa_1;
			struct RSYNa RSYNa_1;
		} C1;
	} S1;
};




extern struct E1Q1SB1_t E1Q1SB1;
extern struct E1Q1BP2_t E1Q1BP2;
extern struct E1Q1BP3_t E1Q1BP3;
extern struct E1Q2SB1_t E1Q2SB1;
extern struct E1Q3SB1_t E1Q3SB1;
extern struct E1Q3KA1_t E1Q3KA1;
extern struct E1Q3KA2_t E1Q3KA2;
extern struct E1Q3KA3_t E1Q3KA3;
extern struct D1Q1SB1_t D1Q1SB1;
extern struct D1Q1BP2_t D1Q1BP2;
extern struct D1Q1BP3_t D1Q1BP3;
extern struct D1Q1SB4_t D1Q1SB4;


#ifdef __cplusplus /* If this is a C++ compiler, end C linkage */
}
#endif

#endif
