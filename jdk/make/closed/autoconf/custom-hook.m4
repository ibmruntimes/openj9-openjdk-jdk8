# ===========================================================================
# (c) Copyright IBM Corp. 2017, 2019 All Rights Reserved
# ===========================================================================
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
#
# IBM designates this particular file as subject to the "Classpath" exception
# as provided by IBM in the LICENSE file that accompanied this code.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, see <http://www.gnu.org/licenses/>.
# ===========================================================================

AC_DEFUN_ONCE([CUSTOM_EARLY_HOOK],
[
  # Where are the OpenJ9 sources.
  OPENJ9OMR_TOPDIR="$SRC_ROOT/omr"
  OPENJ9_TOPDIR="$SRC_ROOT/openj9"

  if ! test -d "$OPENJ9_TOPDIR" ; then
    AC_MSG_ERROR(["Cannot locate the path to OpenJ9 sources: $OPENJ9_TOPDIR! Try 'bash get_source.sh' and restart configure"])
  fi

  if ! test -d "$OPENJ9OMR_TOPDIR" ; then
    AC_MSG_ERROR(["Cannot locate the path to OMR sources: $OPENJ9OMR_TOPDIR! Try 'bash get_source.sh' and restart configure"])
  fi

  AC_SUBST(OPENJ9OMR_TOPDIR)
  AC_SUBST(OPENJ9_TOPDIR)
  AC_SUBST(CONFIG_SHELL)

  OPENJ9_PLATFORM_SETUP
  OPENJDK_VERSION_DETAILS
  OPENJ9_CONFIGURE_CMAKE
  OPENJ9_CONFIGURE_COMPILERS
  OPENJ9_CONFIGURE_CUDA
  OPENJ9_CONFIGURE_DDR

  if test "x$OPENJDK_TARGET_OS" = xwindows ; then
    BASIC_SETUP_OUTPUT_DIR
    TOOLCHAIN_SETUP_VISUAL_STUDIO_ENV
    TOOLCHAIN_SETUP_MSVCP_DLL
  fi

  AC_SUBST(MSVCP_DLL)

  OPENJ9_THIRD_PARTY_REQUIREMENTS
])

AC_DEFUN([OPENJ9_CONFIGURE_CMAKE],
[
  AC_ARG_WITH(cmake, [AS_HELP_STRING([--with-cmake], [enable building openJ9 with CMake])],
    [
      if test "x$with_cmake" != x ; then
        CMAKE=$with_cmake
      fi
      with_cmake=yes
    ],
    [with_cmake=no])
  if test "$with_cmake" == yes ; then
    AC_PATH_PROG([CMAKE], [cmake])
    if test "x$CMAKE" == x ; then
      AC_MSG_ERROR([Could not find CMake])
    fi
    OPENJ9_ENABLE_CMAKE=true
  else
    OPENJ9_ENABLE_CMAKE=false
  fi
  AC_SUBST(OPENJ9_ENABLE_CMAKE)
])

AC_DEFUN([OPENJ9_CONFIGURE_COMPILERS],
[
  AC_ARG_WITH(openj9-cc, [AS_HELP_STRING([--with-openj9-cc], [build OpenJ9 with a specific C compiler])],
    [OPENJ9_CC=$with_openj9_cc],
    [OPENJ9_CC=])

  AC_ARG_WITH(openj9-cxx, [AS_HELP_STRING([--with-openj9-cxx], [build OpenJ9 with a specific C++ compiler])],
    [OPENJ9_CXX=$with_openj9_cxx],
    [OPENJ9_CXX=])

  AC_ARG_WITH(openj9-developer-dir, [AS_HELP_STRING([--with-openj9-developer-dir], [build OpenJ9 with a specific Xcode version])],
    [OPENJ9_DEVELOPER_DIR=$with_openj9_developer_dir],
    [OPENJ9_DEVELOPER_DIR=])

  AC_SUBST(OPENJ9_CC)
  AC_SUBST(OPENJ9_CXX)
  AC_SUBST(OPENJ9_DEVELOPER_DIR)
])

AC_DEFUN([OPENJ9_CONFIGURE_CUDA],
[
  AC_ARG_WITH(cuda, [AS_HELP_STRING([--with-cuda], [use this directory as CUDA_HOME])],
    [
      if test -d "$with_cuda" ; then
        OPENJ9_CUDA_HOME=$with_cuda
      else
        AC_MSG_ERROR([CUDA not found at $with_cuda])
      fi
    ]
  )

  AC_ARG_WITH(gdk, [AS_HELP_STRING([--with-gdk], [use this directory as GDK_HOME])],
    [
      if test -d "$with_gdk" ; then
        OPENJ9_GDK_HOME=$with_gdk
      else
        AC_MSG_ERROR([GDK not found at $with_gdk])
      fi
    ]
  )

  AC_MSG_CHECKING([for cuda])
  AC_ARG_ENABLE([cuda], [AS_HELP_STRING([--enable-cuda], [enable CUDA support @<:@disabled@:>@])])
  if test "x$enable_cuda" = xyes ; then
    AC_MSG_RESULT([yes (explicitly set)])
    OPENJ9_ENABLE_CUDA=true
  elif test "x$enable_cuda" = xno ; then
    AC_MSG_RESULT([no])
    OPENJ9_ENABLE_CUDA=false
  elif test "x$enable_cuda" = x ; then
    AC_MSG_RESULT([no (default)])
    OPENJ9_ENABLE_CUDA=false
  else
    AC_MSG_ERROR([--enable-cuda accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_CUDA)
  AC_SUBST(OPENJ9_CUDA_HOME)
  AC_SUBST(OPENJ9_GDK_HOME)
])

AC_DEFUN([OPENJ9_CONFIGURE_DDR],
[
  AC_MSG_CHECKING([for ddr])
  AC_ARG_ENABLE([ddr], [AS_HELP_STRING([--enable-ddr], [enable DDR support @<:@disabled@:>@])])
  if test "x$enable_ddr" = xyes ; then
    AC_MSG_RESULT([yes (explicitly enabled)])
    OPENJ9_ENABLE_DDR=true
  elif test "x$enable_ddr" = xno ; then
    AC_MSG_RESULT([no (explicitly disabled)])
    OPENJ9_ENABLE_DDR=false
  elif test "x$enable_ddr" = x ; then
    case "$OPENJ9_PLATFORM_CODE" in
      ap64|oa64|wa64|wi32|xa64|xl64|xz64)
        AC_MSG_RESULT([yes (default for $OPENJ9_PLATFORM_CODE)])
        OPENJ9_ENABLE_DDR=true
        ;;
      *)
        AC_MSG_RESULT([no (default for $OPENJ9_PLATFORM_CODE)])
        OPENJ9_ENABLE_DDR=false
        ;;
    esac
  else
    AC_MSG_ERROR([--enable-ddr accepts no argument])
  fi

  AC_SUBST(OPENJ9_ENABLE_DDR)
])

AC_DEFUN([OPENJ9_PLATFORM_EXTRACT_VARS_FROM_CPU],
[
  # Convert openjdk cpu names to openj9 names
  case "$1" in
    x86_64)
      OPENJ9_CPU=x86-64
      ;;
    powerpc64le)
      OPENJ9_CPU=ppc-64_le
      ;;
    s390x)
      OPENJ9_CPU=390-64
      ;;
    powerpc64)
      OPENJ9_CPU=ppc-64
      ;;
    *)
      AC_MSG_ERROR([unsupported OpenJ9 cpu $1])
      ;;
  esac
])

AC_DEFUN_ONCE([OPENJ9_PLATFORM_SETUP],
[
  AC_ARG_WITH(noncompressedrefs, [AS_HELP_STRING([--with-noncompressedrefs],
    [build non-compressedrefs vm (large heap)])])

  OPENJ9_PLATFORM_EXTRACT_VARS_FROM_CPU($build_cpu)
  if test "x$with_noncompressedrefs" != x -o "x$OPENJDK_TARGET_CPU_BITS" = x32 ; then
    OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_${OPENJ9_CPU}"
    OPENJ9_LIBS_SUBDIR=default
  else
    OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_${OPENJ9_CPU}_cmprssptrs"
    OPENJ9_LIBS_SUBDIR=compressedrefs
  fi

  if test "x$OPENJ9_CPU" = xx86-64 ; then
    if test "x$OPENJDK_BUILD_OS" = xlinux ; then
      OPENJ9_PLATFORM_CODE=xa64
    elif test "x$OPENJDK_BUILD_OS" = xwindows ; then
      OPENJ9_PLATFORM_CODE=wa64
      if test "x$OPENJ9_LIBS_SUBDIR" = xdefault ; then
        if test "x$OPENJDK_TARGET_CPU_BITS" = x32 ; then
          OPENJ9_PLATFORM_CODE=wi32
          OPENJ9_BUILDSPEC="win_x86"
        else
          OPENJ9_BUILDSPEC="win_x86-64"
        fi
      else
        OPENJ9_BUILDSPEC="win_x86-64_cmprssptrs"
      fi
    elif test "x$OPENJDK_BUILD_OS" = xmacosx ; then
      OPENJ9_PLATFORM_CODE=oa64
      if test "x$OPENJ9_LIBS_SUBDIR" = xdefault ; then
        OPENJ9_BUILDSPEC="osx_x86-64"
      else
        OPENJ9_BUILDSPEC="osx_x86-64_cmprssptrs"
      fi
    else
      AC_MSG_ERROR([Unsupported OpenJ9 platform ${OPENJDK_BUILD_OS}!])
    fi
  elif test "x$OPENJ9_CPU" = xppc-64_le ; then
    OPENJ9_PLATFORM_CODE=xl64
    if test "x$OPENJ9_LIBS_SUBDIR" = xdefault ; then
      OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_ppc-64_le_gcc"
    else
      OPENJ9_BUILDSPEC="${OPENJDK_BUILD_OS}_ppc-64_cmprssptrs_le_gcc"
    fi
  elif test "x$OPENJ9_CPU" = x390-64 ; then
    OPENJ9_PLATFORM_CODE=xz64
  elif test "x$OPENJ9_CPU" = xppc-64 ; then
    OPENJ9_PLATFORM_CODE=ap64
  else
    AC_MSG_ERROR([Unsupported OpenJ9 cpu ${OPENJ9_CPU}!])
  fi

  AC_SUBST(OPENJ9_BUILDSPEC)
  AC_SUBST(OPENJ9_PLATFORM_CODE)
  AC_SUBST(OPENJ9_LIBS_SUBDIR)
])

AC_DEFUN_ONCE([OPENJDK_VERSION_DETAILS],
[
  # Source the closed version numbers
  . $SRC_ROOT/jdk/make/closed/autoconf/openj9ext-version-numbers

  AC_SUBST(JDK_MOD_VERSION)
  AC_SUBST(JDK_FIX_VERSION)

  OPENJDK_SHA=`git -C $SRC_ROOT rev-parse --short HEAD`
  # Find first rev tagged by jdk8u* but not containing "_openj9"
  LAST_TAGGED_SHA=`git -C $SRC_ROOT rev-list --exclude="*_openj9*" --tags="jdk8u*" --topo-order --max-count=1 2>/dev/null`
  if test "x$LAST_TAGGED_SHA" != x ; then
    # Choose the latest tag when there is more than one for the same SHA.
    OPENJDK_TAG=`git -C $TOPDIR tag --points-at "$LAST_TAGGED_SHA" | grep '-' | sort -V | tail -1`
  else
    OPENJDK_TAG=
  fi

  AC_SUBST(OPENJDK_SHA)
  AC_SUBST(OPENJDK_TAG)

  # Outer [ ] to quote m4.
  [ USERNAME=`$ECHO "$USER" | $TR -d -c '[a-z][A-Z][0-9]'` ]
  AC_SUBST(USERNAME)
])

AC_DEFUN_ONCE([OPENJ9_THIRD_PARTY_REQUIREMENTS],
[
  # check 3rd party library requirement for UMA
  AC_ARG_WITH(freemarker-jar, [AS_HELP_STRING([--with-freemarker-jar],
    [path to freemarker.jar (used to build OpenJ9 build tools)])])

  if test "x$with_freemarker_jar" == x ; then
    printf "\n"
    printf "The FreeMarker library is required to build the OpenJ9 build tools\n"
    printf "and has to be provided during configure process.\n"
    printf "\n"
    printf "Download the FreeMarker library and unpack it into an arbitrary directory:\n"
    printf "\n"
    printf "wget https://sourceforge.net/projects/freemarker/files/freemarker/2.3.8/freemarker-2.3.8.tar.gz/download -O freemarker-2.3.8.tar.gz\n"
    printf "\n"
    printf "tar -xzf freemarker-2.3.8.tar.gz\n"
    printf "\n"
    printf "Then run configure with '--with-freemarker-jar=<freemarker_jar>'\n"
    printf "\n"

    AC_MSG_NOTICE([Could not find freemarker.jar])
    AC_MSG_ERROR([Cannot continue])
  fi

  if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
    FREEMARKER_JAR=`$CYGPATH -m "$with_freemarker_jar"`
  else
    FREEMARKER_JAR=$with_freemarker_jar
  fi

  AC_SUBST(FREEMARKER_JAR)
])

AC_DEFUN_ONCE([CUSTOM_LATE_HOOK],
[
  CONFIGURE_OPENSSL

  COMPILER=$CXX
  if test "x$OPENJDK_TARGET_OS" = xaix ; then
    # xlc -qversion output typically looks like
    #     IBM XL C/C++ for AIX, V11.1 (5724-X13)
    #     Version: 11.01.0000.0015
    COMPILER_VERSION_OUTPUT=`$COMPILER -qversion 2>&1`
    # Collapse compiler output into a single line
    COMPILER_VERSION_STRING=`$ECHO $COMPILER_VERSION_OUTPUT`
  elif test "x$OPENJDK_TARGET_OS" = xwindows ; then
    # There is no specific version flag, but all output starts with a version string.
    # First line typically looks something like:
    # Microsoft (R) 32-bit C/C++ Optimizing Compiler Version 16.00.40219.01 for 80x86
    COMPILER_VERSION_OUTPUT=`$COMPILER 2>&1 | $HEAD -n 1 | $TR -d '\r'`
    # Collapse compiler output into a single line
    COMPILER_VERSION_STRING=`$ECHO $COMPILER_VERSION_OUTPUT`
  else
    # gcc --version output typically looks like
    #     gcc (Ubuntu/Linaro 4.8.1-10ubuntu9) 4.8.1
    #     Copyright (C) 2013 Free Software Foundation, Inc.
    #     This is free software; see the source for copying conditions.  There is NO
    #     warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    COMPILER_VERSION_OUTPUT=`$COMPILER --version 2>&1`
    # Remove Copyright and legalese from version string, and
    # collapse into a single line
    COMPILER_VERSION_STRING=`$ECHO $COMPILER_VERSION_OUTPUT | \
        $SED -e 's/ *Copyright .*//'`
  fi
  AC_SUBST(COMPILER_VERSION_STRING)

  CLOSED_AUTOCONF_DIR="$SRC_ROOT/jdk/make/closed/autoconf"

  # Create the custom-spec.gmk
  AC_CONFIG_FILES([$OUTPUT_ROOT/custom-spec.gmk:$CLOSED_AUTOCONF_DIR/custom-spec.gmk.in])

  # explicitly disable classlist generation
  ENABLE_GENERATE_CLASSLIST="false"
])

AC_DEFUN([TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL],
[
  POSSIBLE_MSVCP_DLL="$1"
  METHOD="$2"
  if test -e "$POSSIBLE_MSVCP_DLL" ; then
    AC_MSG_NOTICE([Found msvcp100.dll at $POSSIBLE_MSVCP_DLL using $METHOD])

    # Need to check if the found msvcp is correct architecture
    AC_MSG_CHECKING([found msvcp100.dll architecture])
    MSVCP_DLL_FILETYPE=`$FILE -b "$POSSIBLE_MSVCP_DLL"`
    if test "x$OPENJDK_TARGET_CPU_BITS" = x32 ; then
      CORRECT_MSVCP_ARCH=386
    else
      CORRECT_MSVCP_ARCH=x86-64
    fi
    if $ECHO "$MSVCP_DLL_FILETYPE" | $GREP $CORRECT_MSVCP_ARCH 2>&1 > /dev/null ; then
      AC_MSG_RESULT([ok])
      MSVCP_DLL="$POSSIBLE_MSVCP_DLL"
      AC_MSG_CHECKING([for msvcp100.dll])
      AC_MSG_RESULT([$MSVCP_DLL])
    else
      AC_MSG_RESULT([incorrect, ignoring])
      AC_MSG_NOTICE([The file type of the located msvcp100.dll is $MSVCP_DLL_FILETYPE])
    fi
  fi
])

AC_DEFUN([TOOLCHAIN_SETUP_MSVCP_DLL],
[
  AC_ARG_WITH(msvcp-dll, [AS_HELP_STRING([--with-msvcp-dll],
      [copy this msvcp100.dll into the built JDK (Windows only) @<:@probed@:>@])])

  if test "x$with_msvcp_dll" != x ; then
    # If given explicitly by user, do not probe. If not present, fail directly.
    TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$with_msvcp_dll], [--with-msvcp-dll])
    if test "x$MSVCP_DLL" = x ; then
      AC_MSG_ERROR([Could not find a proper msvcp100.dll as specified by --with-msvcp-dll])
    fi
  fi

  if test "x$MSVCP_DLL" = x ; then
    # Probe: Using well-known location from Visual Studio 10.0
    if test "x$VCINSTALLDIR" != x ; then
      CYGWIN_VC_INSTALL_DIR="$VCINSTALLDIR"
      BASIC_WINDOWS_REWRITE_AS_UNIX_PATH(CYGWIN_VC_INSTALL_DIR)
      if test "x$OPENJDK_TARGET_CPU_BITS" = x64 ; then
        POSSIBLE_MSVCP_DLL="$CYGWIN_VC_INSTALL_DIR/redist/x64/Microsoft.VC100.CRT/msvcp100.dll"
      else
        POSSIBLE_MSVCP_DLL="$CYGWIN_VC_INSTALL_DIR/redist/x86/Microsoft.VC100.CRT/msvcp100.dll"
      fi
      TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$POSSIBLE_MSVCP_DLL], [well-known location in VCINSTALLDIR])
    fi
  fi

  if test "x$MSVCP_DLL" = x ; then
    # Probe: Check in the Boot JDK directory.
    POSSIBLE_MSVCP_DLL="$BOOT_JDK/bin/msvcp100.dll"
    TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$POSSIBLE_MSVCP_DLL], [well-known location in Boot JDK])
  fi

  if test "x$MSVCP_DLL" = x ; then
    # Probe: Look in the Windows system32 directory
    CYGWIN_SYSTEMROOT="$SYSTEMROOT"
    BASIC_WINDOWS_REWRITE_AS_UNIX_PATH(CYGWIN_SYSTEMROOT)
    POSSIBLE_MSVCP_DLL="$CYGWIN_SYSTEMROOT/system32/msvcp100.dll"
    TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$POSSIBLE_MSVCP_DLL], [well-known location in SYSTEMROOT])
  fi

  if test "x$MSVCP_DLL" = x ; then
    # Probe: If Visual Studio Express is installed, there is usually one with the debugger
    if test "x$VS100COMNTOOLS" != x ; then
      CYGWIN_VS_TOOLS_DIR="$VS100COMNTOOLS/.."
      BASIC_WINDOWS_REWRITE_AS_UNIX_PATH(CYGWIN_VS_TOOLS_DIR)
      if test "x$OPENJDK_TARGET_CPU_BITS" = x64 ; then
        POSSIBLE_MSVCP_DLL=`$FIND "$CYGWIN_VS_TOOLS_DIR" -name msvcp100.dll | $GREP -i /x64/ | $HEAD --lines 1`
      else
        POSSIBLE_MSVCP_DLL=`$FIND "$CYGWIN_VS_TOOLS_DIR" -name msvcp100.dll | $GREP -i /x86/ | $HEAD --lines 1`
      fi
      TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$POSSIBLE_MSVCP_DLL], [search of VS100COMNTOOLS])
    fi
  fi

  if test "x$MSVCP_DLL" = x ; then
    # Probe: Search wildly in the VCINSTALLDIR. We've probably lost by now.
    # (This was the original behaviour ; kept since it might turn up something)
    if test "x$CYGWIN_VC_INSTALL_DIR" != x ; then
      if test "x$OPENJDK_TARGET_CPU_BITS" = x64 ; then
        POSSIBLE_MSVCP_DLL=`$FIND "$CYGWIN_VC_INSTALL_DIR" -name msvcp100.dll | $GREP x64 | $HEAD --lines 1`
      else
        POSSIBLE_MSVCP_DLL=`$FIND "$CYGWIN_VC_INSTALL_DIR" -name msvcp100.dll | $GREP x86 | $GREP -v ia64 | $GREP -v x64 | $HEAD --lines 1`
        if test "x$POSSIBLE_MSVCP_DLL" = x ; then
          # We're grasping at straws now...
          POSSIBLE_MSVCP_DLL=`$FIND "$CYGWIN_VC_INSTALL_DIR" -name msvcp100.dll | $HEAD --lines 1`
        fi
      fi

      TOOLCHAIN_CHECK_POSSIBLE_MSVCP_DLL([$POSSIBLE_MSVCP_DLL], [search of VCINSTALLDIR])
    fi
  fi

  if test "x$MSVCP_DLL" = x ; then
    AC_MSG_CHECKING([for msvcp100.dll])
    AC_MSG_RESULT([no])
    AC_MSG_ERROR([Could not find msvcp100.dll. Please specify using --with-msvcp-dll.])
  fi

  BASIC_FIXUP_PATH(MSVCP_DLL)
])

AC_DEFUN([CONFIGURE_OPENSSL],
[
  AC_ARG_WITH(openssl, [AS_HELP_STRING([--with-openssl],
    [Use either fetched | system | <path to openssl 1.0.2 (and above)])])

  AC_ARG_ENABLE(openssl-bundling, [AS_HELP_STRING([--enable-openssl-bundling],
      [enable bundling of the openssl crypto library with the jdk build])])

  WITH_OPENSSL=yes

  if test "x$with_openssl" = x ; then
    # User doesn't want to build with OpenSSL. No need to build openssl libraries
    WITH_OPENSSL=no
  else
    AC_MSG_CHECKING([for OPENSSL])
    BUNDLE_OPENSSL="$enable_openssl_bundling"
    BUILD_OPENSSL=no

    # If not specified, default is to not bundle openssl
    if test "x$BUNDLE_OPENSSL" = x ; then
      BUNDLE_OPENSSL=no
    fi

    # Process --with-openssl=fetched
    if test "x$with_openssl" = xfetched ; then
      if test "x$OPENJDK_BUILD_OS" = xwindows ; then
        AC_MSG_RESULT([no])
        printf "On Windows, value of \"fetched\" is currently not supported with --with-openssl. Please build OpenSSL using VisualStudio outside cygwin and specify the path with --with-openssl\n"
        AC_MSG_ERROR([Cannot continue])
      fi

      if test -d "$SRC_ROOT/openssl" ; then
        OPENSSL_DIR="$SRC_ROOT/openssl"
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
        if test -s "$OPENSSL_DIR/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
          BUILD_OPENSSL=no
        else
          BUILD_OPENSSL=yes
        fi

        if test "x$BUNDLE_OPENSSL" = xyes ; then
          OPENSSL_BUNDLE_LIB_PATH="$OPENSSL_DIR"
        fi
        AC_MSG_RESULT([yes])
      else
        AC_MSG_RESULT([no])
        printf "$SRC_ROOT/openssl is not found.\n"
        printf "  run get_source.sh --openssl-version=<version as 1.0.2 or later>\n"
        printf "  Then, run configure with '--with-openssl=fetched'\n"
        AC_MSG_ERROR([Cannot continue])
      fi

    # Process --with-openssl=system
    elif test "x$with_openssl" = xsystem ; then
      if test "x$OPENJDK_BUILD_OS" = xwindows ; then
        AC_MSG_RESULT([no])
        printf "On Windows, value of \"system\" is currently not supported with --with-openssl. Please build OpenSSL using VisualStudio outside cygwin and specify the path with --with-openssl\n"
        AC_MSG_ERROR([Cannot continue])
      fi

      # We can use the system installed openssl only when it is package installed.
      # If not package installed, fail with an error message.
      # PKG_CHECK_MODULES will setup the variable OPENSSL_CFLAGS and OPENSSL_LIB when successful.
      PKG_CHECK_MODULES(OPENSSL, openssl >= 1.0.2, [FOUND_OPENSSL=yes], [FOUND_OPENSSL=no])

      if test "x$FOUND_OPENSSL" != xyes; then
        AC_MSG_ERROR([Unable to find openssl 1.0.2(and above) installed on System. Please use other options for '--with-openssl'])
      fi

      # The crypto library bundling option is not available when --with-openssl=system.
      if test "x$BUNDLE_OPENSSL" = xyes ; then
        AC_MSG_RESULT([no])
        printf "The option --enable_openssl_bundling is not available with --with-openssl=system. Use option fetched or openssl path to bundle crypto library\n"
        AC_MSG_ERROR([Cannot continue])
      fi

    # Process --with-openssl=/custom/path/where/openssl/is/present
    # As the value is not fetched or system, assume user specified the
    # path where openssl is installed
    else
      OPENSSL_DIR="$with_openssl"
      BASIC_FIXUP_PATH(OPENSSL_DIR)
      if test -s "$OPENSSL_DIR/include/openssl/evp.h" ; then
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include"
        if test "x$BUNDLE_OPENSSL" = xyes ; then
          if test "x$OPENJDK_BUILD_OS_ENV" = xwindows.cygwin ; then
            if test -d "$OPENSSL_DIR/bin" ; then
              OPENSSL_BUNDLE_LIB_PATH="$OPENSSL_DIR/bin"
            else
              OPENSSL_BUNDLE_LIB_PATH="$OPENSSL_DIR"
            fi
          else
            if test -s "$OPENSSL_DIR/lib/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
              if test "x$BUNDLE_OPENSSL" = xyes ; then
                # On Mac OSX, create local copy of the crypto library to update @rpath
                # as the default is /usr/local/lib.
                if test "x$OPENJDK_BUILD_OS" = xmacosx ; then
                  LOCAL_CRYPTO="$TOPDIR/openssl"
                  $MKDIR -p "${LOCAL_CRYPTO}"
                  $CP "${OPENSSL_DIR}/libcrypto.1.1.dylib" "${LOCAL_CRYPTO}"
                  $CP "${OPENSSL_DIR}/libcrypto.1.0.0.dylib" "${LOCAL_CRYPTO}"
                  $CP -a "${OPENSSL_DIR}/libcrypto.dylib" "${LOCAL_CRYPTO}"
                  OPENSSL_BUNDLE_LIB_PATH="${LOCAL_CRYPTO}"
                else
                  OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}/lib"
                fi
              fi
            elif test -s "$OPENSSL_DIR/${LIBRARY_PREFIX}crypto${SHARED_LIBRARY_SUFFIX}" ; then
              if test "x$BUNDLE_OPENSSL" = xyes ; then
                # On Mac OSX, create local copy of the crypto library to update @rpath
                # as the default is /usr/local/lib.
                if test "x$OPENJDK_BUILD_OS" = xmacosx ; then
                  LOCAL_CRYPTO="$TOPDIR/openssl"
                  $MKDIR -p "${LOCAL_CRYPTO}"
                  $CP "${OPENSSL_DIR}/libcrypto.1.1.dylib" "${LOCAL_CRYPTO}"
                  $CP "${OPENSSL_DIR}/libcrypto.1.0.0.dylib" "${LOCAL_CRYPTO}"
                  $CP -a "${OPENSSL_DIR}/libcrypto.dylib" "${LOCAL_CRYPTO}"
                  OPENSSL_BUNDLE_LIB_PATH="${LOCAL_CRYPTO}"
                else
                  OPENSSL_BUNDLE_LIB_PATH="${OPENSSL_DIR}"
                fi
              fi
            else
              AC_MSG_RESULT([no])
              AC_MSG_ERROR([Unable to find crypto library to bundle in specified location $OPENSSL_DIR])
            fi
          fi
        fi
      else
        # openssl is not found in user specified location. Abort.
        AC_MSG_RESULT([no])
        AC_MSG_ERROR([Unable to find openssl in specified location $OPENSSL_DIR])
      fi
      AC_MSG_RESULT([yes])
    fi

    AC_MSG_CHECKING([if we should bundle openssl])
    AC_MSG_RESULT([$BUNDLE_OPENSSL])
  fi

  AC_SUBST(OPENSSL_BUNDLE_LIB_PATH)
  AC_SUBST(OPENSSL_DIR)
  AC_SUBST(WITH_OPENSSL)
  AC_SUBST(BUILD_OPENSSL)
  AC_SUBST(OPENSSL_CFLAGS)
])

