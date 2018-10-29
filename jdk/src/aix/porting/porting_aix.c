/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2018, 2018 All Rights Reserved
 * ===========================================================================
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * IBM designates this particular file as subject to the "Classpath" exception
 * as provided by IBM in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
 * ===========================================================================
 */

#include "porting_aix.h"

#include <stdint.h>
#include <string.h>
#include <sys/ldr.h>

int
dladdr(void *addr, Dl_info *info)
{
	/*
	 * The filename returned in info->dli_fname will point within this array.
	 * As such, this implementation is not thread-safe.
	 */
	static struct ld_info infoBuffers[200];

	memset(info, 0, sizeof(*info));

	if ((NULL != addr) && (-1 != loadquery(L_GETINFO, infoBuffers, sizeof(infoBuffers)))) {
		int32_t pass = 1;
		struct ld_info *module = infoBuffers;
		uintptr_t textaddr = (uintptr_t)addr;

		/* find the module in the list */
		for (;;) {
			uintptr_t textorg = (uintptr_t)module->ldinfo_textorg;
			uintptr_t textend = textorg + (uintptr_t)module->ldinfo_textsize;

			if ((textorg <= textaddr) && (textaddr < textend)) {
				/* found it */
				info->dli_fname = module->ldinfo_filename;
				return 1;
			} else {
				uintptr_t nextoffset = (uintptr_t)module->ldinfo_next;

				if (0 != nextoffset) {
					module = (struct ld_info *)((char *)module + nextoffset);
				} else {
					/* end of the module list */
					if (pass < 2) {
						/*
						 * This function is commonly called where the first parameter is
						 * specified using the name of a function. On PPC, this yields
						 * the address of function descriptor which must be dereferenced.
						 * We now dereference the given address and make a second pass
						 * through the module list.
						 */
						pass += 1;
						module = infoBuffers;
						textaddr = (uintptr_t)*(void **)addr;
					} else {
						break;
					}
				}
			}
		}
	}

	return 0;
}
