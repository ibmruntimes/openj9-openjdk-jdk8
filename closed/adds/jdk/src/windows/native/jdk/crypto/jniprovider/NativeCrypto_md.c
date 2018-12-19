/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2019, 2019 All Rights Reserved
 * ===========================================================================
 *
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
 *
 * ===========================================================================
 */

#include <windows.h>

#include "NativeCrypto_md.h"

/* Load the crypto library (return NULL on error) */
void * load_crypto_library() {
    void * result = NULL;
    const char *libname;
    const char *oldname;

#ifdef WIN32
    libname = "libcrypto-1_1.dll";
#else
    libname = "libcrypto-1_1-x64.dll"
#endif

    oldname = "libeay32.dll";

    result = LoadLibrary(libname);
    
    if (result == NULL) {
        result = LoadLibrary(oldname);
    }

    return result;
}

/* Unload the crypto library */
void unload_crypto_library(void *handle) {
	FreeLibrary(handle);
}

/* Find the symbol in the crypto library (return NULL if not found) */
void * find_crypto_symbol(void *handle, const char *symname) {
    void * symptr;

    symptr =  GetProcAddress(handle, symname);

    return symptr;
}