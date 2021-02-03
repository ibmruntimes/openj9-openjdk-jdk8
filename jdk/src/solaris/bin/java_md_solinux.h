/*
 * Copyright (c) 2013, 2020, Oracle and/or its affiliates. All rights reserved.
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
 * ===========================================================================
 * (c) Copyright IBM Corp. 2021, 2021 All Rights Reserved
 * ===========================================================================
 */

#ifndef JAVA_MD_SOLINUX_H
#define JAVA_MD_SOLINUX_H

#include <sys/time.h>
#ifdef __solaris__
/*
 * Support for doing cheap, accurate interval timing.
 */
#define CounterGet()              (gethrtime()/1000)
#define Counter2Micros(counts)    (counts)
#else  /* ! __solaris__ */
uint64_t CounterGet(void);
#define Counter2Micros(counts)    (counts)
#endif /* __solaris__ */

/* pointer to environment */
extern char **environ;

/*
 *      A collection of useful strings. One should think of these as #define
 *      entries, but actual strings can be more efficient (with many compilers).
 */
#ifdef __solaris__
static const char *system_dir   = "/usr/jdk";
static const char *user_dir     = "/jdk";
#else /* !__solaris__, i.e. Linux, AIX,.. */
static const char *system_dir   = "/usr/java";
static const char *user_dir     = "/java";
#endif

#include <dlfcn.h>
#ifdef __solaris__
#include <thread.h>
#else
#include <pthread.h>
#endif

#ifdef AIX
#define ZLIBNX_PATH "/usr/opt/zlibNX/lib"

#ifndef POWER_9
#define POWER_9 0x20000 /* 9 class CPU */
#endif

#ifndef POWER_10
#define POWER_10 0x40000 /* 10 class CPU */
#endif

#define power_9_andup() ((POWER_9  == _system_configuration.implementation) \
                        || (POWER_10 == _system_configuration.implementation))

#ifndef SC_NX_CAP
#define SC_NX_CAP 60
#endif

#ifndef NX_GZIP_PRESENT
#define NX_GZIP_PRESENT 0x00000001
#endif

#define power_nx_gzip() (0 != ((long)getsystemcfg(SC_NX_CAP) & NX_GZIP_PRESENT))
#endif /* AIX */

#endif /* JAVA_MD_SOLINUX_H */
