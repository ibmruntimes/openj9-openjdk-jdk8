#!/bin/bash
#
# ===========================================================================
# (c) Copyright IBM Corp. 2017 All Rights Reserved
# ===========================================================================
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
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

set -euo pipefail

echo "Common defs"

# shellcheck disable=SC1091
source import-common.sh

rm -rf $WORKSPACE/openj9
rm -rf $WORKSPACE/openjdk

mkdir $WORKSPACE/openj9
mkdir $WORKSPACE/openjdk
mkdir $WORKSPACE/openjdk/mirror

cd $WORKSPACE/openj9

# Clone current openj9
echo "Clone current openj9 extensions"
git clone $GITHUB_IBM/$J9REPOSITORY.git
cd $J9REPOSITORY
git fetch --tags
OLDTAG=$(git describe --abbrev=0 --tags) 
echo "Current openjdk level is $OLDTAG"


# Clone current openjdk
echo "Get base openjdk repository" 
cd $WORKSPACE/openjdk/mirror
git init
git clone --bare hg::http://hg.openjdk.java.net/jdk8u/jdk8u

cd jdk8u.git

git filter-branch -f --index-filter 'git rm -r -f -q --cached --ignore-unmatch .hg .hgignore .hgtags README get_source.sh' --prune-empty --tag-name-filter cat -- --all

cd ..
git pull jdk8u
git fetch --tags jdk8u
rm -rf jdk8u.git

NEWTAG=$(git describe --abbrev=0 --tags)
echo "Latest openjdk level is $NEWTAG"

if [ $NEWTAG != $OLDTAG ]
then
  
  echo "New tag $NEWTAG, updating master branch"
  cd $WORKSPACE/openj9/$J9REPOSITORY
  git checkout master
  git fetch $WORKSPACE/openjdk/mirror
  git merge --allow-unrelated-histories -m "Merge base $NEWTAG" FETCH_HEAD

  for module in "${modules[@]}"
    do
      mkdir "$WORKSPACE/openjdk/$module"
      cd $WORKSPACE/openjdk/$module
      git init
      echo "Clone $module"
      git clone --bare hg::http://hg.openjdk.java.net/jdk8u/jdk8u/$module || exit 1
      cd $module.git
      echo "GIT filter on $module"
      git filter-branch -f --index-filter "git rm -f -q --cached --ignore-unmatch .hgignore .hgtags && git ls-files -s | sed \"s|\t\\\"*|&$module/|\" | GIT_INDEX_FILE=\$GIT_INDEX_FILE.new git update-index --index-info && mv \"\$GIT_INDEX_FILE.new\" \"\$GIT_INDEX_FILE\"" --prune-empty --tag-name-filter cat -- --all

      cd ..
      echo "GIT pull on $module"
      git pull $module
      rm -rf $module.git
      cd $WORKSPACE/openj9/$J9REPOSITORY 
      git fetch $WORKSPACE/openjdk/$module
      git merge --allow-unrelated-histories -m "Merge $module $NEWTAG" FETCH_HEAD
    done
  cd $WORKSPACE/openj9/$J9REPOSITORY
  git push origin master
  
  echo "Pulling in changes to openj9 branch"
  git checkout openj9
  git fetch origin master
  git merge --allow-unrelated-histories -m "Merge $NEWTAG into openj9" FETCH_HEAD
  git tag -a $NEWTAG -m "Merge $NEWTAG into openj9"
  git push origin openj9 --tags

else
  echo "No new tag. No update done"
fi

