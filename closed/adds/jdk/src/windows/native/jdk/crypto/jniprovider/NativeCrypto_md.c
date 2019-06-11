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
#include <stdio.h>
#include <jni.h>
#include <sys/stat.h>

#include "NativeCrypto_md.h"

#define JAVA_DLL "java.dll"

/* Prototypes. */
static jboolean GetJREPath(char *path, jint pathsize);
static jboolean GetApplicationHome(char *buf, jint bufsize);
static int JLI_Snprintf(char* buffer, size_t size, const char* format, ...);

/* Load the crypto library (return NULL on error) */
void * load_crypto_library() {
    void * result = NULL;
    const char *libname;
    const char *oldname = "libeay32.dll";
    char opensslpath[MAX_PATH];

#if defined (_WIN64)
    libname = "libcrypto-1_1-x64.dll";
#else
    libname = "libcrypto-1_1.dll";
#endif

    if (GetJREPath(opensslpath, MAX_PATH)) {
        char libpathname[MAX_PATH];
        int rc;
        struct stat s;
        
        rc = JLI_Snprintf(libpathname, sizeof(libpathname), "%s\\bin\\%s", opensslpath, libname);
        if ((rc > 0) && (rc <= MAX_PATH) && (stat(libpathname, &s) == 0)) {
            result = LoadLibrary(libpathname);
        }
        if (result == NULL) {
            rc = JLI_Snprintf(libpathname, sizeof(libpathname), "%s\\bin\\%s", opensslpath, oldname);
            if ((rc > 0) && (rc <= MAX_PATH) && (stat(libpathname, &s) == 0)) {
                result = LoadLibrary(libpathname);
            }
        }
    } else {
        result = LoadLibrary(libname);

        if (result == NULL) {
            result = LoadLibrary(oldname);
        }
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

/*
 * Copyright (c) 1997, 2015, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * Find path to JRE based on .exe's location
 */
jboolean
GetJREPath(char *path, jint pathsize)
{
    if (GetApplicationHome(path, pathsize)) {
    
        char javadll[MAX_PATH];
        struct stat s;
        int rc;

        /* Is JRE co-located with the application? */
        rc = JLI_Snprintf(javadll, sizeof(javadll), "%s\\bin\\" JAVA_DLL, path);
        if ((rc > 0) && (rc <= MAX_PATH) && (stat(javadll, &s) == 0)) {
            return JNI_TRUE;
        }
        /* ensure storage for path + \jre + NULL */
        if ((strlen(path) + 4 + 1) > pathsize) {
            return JNI_FALSE;
        }
        /* Does this app ship a private JRE in <apphome>\jre directory? */
        rc = JLI_Snprintf(javadll, sizeof (javadll), "%s\\jre\\bin\\" JAVA_DLL, path);
        if ((rc > 0) && (rc <= MAX_PATH) && (stat(javadll, &s) == 0)) {
            strcat(path, "\\jre");
            return JNI_TRUE;
        }
    }
    return JNI_FALSE;
}

/*
 * If app is "c:\foo\bin\javac", then put "c:\foo" into buf.
 */
jboolean
GetApplicationHome(char *buf, jint bufsize)
{
    char *cp;
    GetModuleFileName(0, buf, bufsize);
    if ((cp = strrchr(buf, '\\')) != NULL) *cp = '\0'; /* remove .exe file name */
    if ((cp = strrchr(buf, '\\')) == NULL) {
        /* This happens if the application is in a drive root, and
         * there is no bin directory. */
        buf[0] = '\0';
        return JNI_FALSE;
    }
    *cp = '\0';  /* remove the bin\ part */
    return JNI_TRUE;
}

/*
 * windows snprintf does not guarantee a null terminator in the buffer,
 * if the computed size is equal to or greater than the buffer size,
 * as well as error conditions. This function guarantees a null terminator
 * under all these conditions. An unreasonable buffer or size will return
 * an error value. Under all other conditions this function will return the
 * size of the bytes actually written minus the null terminator, similar
 * to ansi snprintf api. Thus when calling this function the caller must
 * ensure storage for the null terminator.
 */
int
JLI_Snprintf(char* buffer, size_t size, const char* format, ...) {
    int rc;
    va_list vl;
    if (size == 0 || buffer == NULL)
        return -1;
    buffer[0] = '\0';
    va_start(vl, format);
    rc = vsnprintf(buffer, size, format, vl);
    va_end(vl);
    /* force a null terminator, if something is amiss */
    if (rc < 0) {
        buffer[size - 1] = '\0';
        return -1;
    } else if (rc == size) {
        /* force a null terminator */
        buffer[size - 1] = '\0';
    }
    return rc;
}
