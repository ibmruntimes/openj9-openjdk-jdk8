/*
 * ===========================================================================
 * (c) Copyright IBM Corp. 2019, 2023 All Rights Reserved
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include "NativeCrypto_md.h"

#if defined(__linux__)
#include <link.h>
#endif /* defined(__linux__) */

/* Load the crypto library (return NULL on error) */
void * load_crypto_library(jboolean traceEnabled)
{
    void * result = NULL;
    int flags = RTLD_NOW;
    size_t i = 0;

    // Library names for OpenSSL 3.x, 1.1.1, 1.1.0, 1.0.2 and symbolic links
    static const char * const libNames[] = {
#if defined(_AIX)
    "libcrypto.a(libcrypto64.so.3)",
    "libcrypto64.so.3",
    "libcrypto.a(libcrypto.so.3)",
    "libcrypto.so.3",
    "libcrypto.a(libcrypto64.so.1.1)",
    "libcrypto.so.1.1",
    "libcrypto.so.1.0.0",
    "libcrypto.a(libcrypto64.so)",
#elif defined(MACOSX)
    "libcrypto.3.dylib",
    "libcrypto.1.1.dylib",
    "libcrypto.1.0.0.dylib",
    "libcrypto.dylib"
#else
    "libcrypto.so.3", // 3.x library name
    "libcrypto.so.1.1",
    "libcrypto.so.1.0.0",
    "libcrypto.so.10",
    "libcrypto.so",
#endif
    };

    // Check to see if we can load the libraries in the order set out above
    for (i = 0; (NULL == result) && (i < sizeof(libNames) / sizeof(libNames[0])); i++) {
        const char * libName = libNames[i];
        flags = RTLD_NOW;

#if defined(AIX)
        if (NULL != strrchr(libName, '('))
            flags |= RTLD_MEMBER;
# endif

        result = dlopen (libName,  flags);
    }

#if defined(__linux__)
    if (traceEnabled && (NULL != result)) {
        struct link_map *map = NULL;
        dlinfo(result, RTLD_DI_LINKMAP, &map);
        fprintf(stderr, "Attempt to load OpenSSL %s\n", map->l_name);
        fflush(stderr);
    }
#endif /* defined(__linux__) */

    return result;
}

/* Unload the crypto library */
void unload_crypto_library(void *handle) {
    (void)dlclose(handle);
}

/* Find the symbol in the crypto library (return NULL if not found) */
void * find_crypto_symbol(void *handle, const char *symname) {
    return  dlsym(handle, symname);
}

