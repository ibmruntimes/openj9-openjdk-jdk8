#!/bin/sh
  
# ===========================================================================
# (c) Copyright IBM Corp. 2018, 2019 All Rights Reserved
# ===========================================================================
# 
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
# 
# ===========================================================================

usage() {
	echo "Usage: $0 [-h|--help] [--openssl-version=<openssl version 1.0.2 and above to download>]"
	echo "where:"
	echo "  -h|--help             print this help, then exit"
	echo "  --openssl-version     OpenSSL version to download. For example, 1.1.1"
	echo ""
	exit 1
}

OPENSSL_VERSION=""
GIT_URL="https://github.com/openssl/openssl.git"

for i in "$@"
do
	case $i in
		-h | --help )
		usage
		;;

		--openssl-version=* )
		OPENSSL_VERSION="${i#*=}"
		;;

		'--' ) # no more options
		usage
		;;

		-*) # bad option
		usage
		;;

		*) # bad option
		usage
		;;
	esac
done

if [ [${OPENSSL_VERSION:0:5} != "1.0.2" ] &&
     [${OPENSSL_VERSION:0:4} != "1.1." ]]; then
	usage
fi

OPENSSL_SOURCE_TAG=$(echo "OpenSSL.${OPENSSL_VERSION}" | sed -e 's/\./_/g' )

if [ -f "openssl/openssl_version.txt" ]; then
	DOWNLOADED_VERSION=$(cat openssl/openssl_version.txt)
	if [ $OPENSSL_SOURCE_TAG = $DOWNLOADED_VERSION ]; then
		echo ""
		echo "OpenSSL of version $OPENSSL_VERSION is already downloaded"
		exit 0
	else
		echo ""
		echo "Cleaning up OpenSSL source code as version already downloaded is different"
		rm -rf openssl
	fi
fi
	
echo ""
echo "Cloning OpenSSL of version $OPENSSL_VERSION"
git clone --depth=1 -b ${OPENSSL_SOURCE_TAG} ${GIT_URL}

echo $OPENSSL_SOURCE_TAG > openssl/openssl_version.txt

