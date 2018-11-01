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

#ifndef PORTING_AIX_H
#define PORTING_AIX_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Dl_info {
	/* pathname of shared object that contains address */
	const char *dli_fname;
#if 0 /* unsupported fields */
	/* base address at which shared object is loaded */
	void *dli_fbase;
	/* name of symbol whose definition overlaps addr */
	const char *dli_sname;
	/* exact address of symbol named in dli_sname */
	void *dli_saddr;
#endif /* unsupported */
} Dl_info;

/*
 * A limited implementation for AIX of the API in glibc on other platforms.
 *
 * Given the address in a code section of the process, return information
 * about the module and function containing that address.
 *
 * @param addr the code address of interest
 * @param info where the module and function information is to be returned
 *
 * @return non-zero on success, zero otherwise
 */
int dladdr(void *addr, Dl_info *info);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* PORTING_AIX_H */
