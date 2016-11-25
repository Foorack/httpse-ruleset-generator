#!/bin/bash

#
# This bash script is used for automaticly pushing generated rulesets to the git
# repository. Please review the ruleset before pushing.
#

function yes_or_no {
    while true; do
        read -p "$* [y/n]: " yn
        case $yn in
            [Yy]*) return 0  ;;  
            [Nn]*) echo "Aborted" ; return  1 ;;
        esac
    done
}

function push_to_git {
    cd ../https-everywhere
    git checkout master
    git fetch origin
    git reset --hard origin/master
    git branch $1
    git checkout $1
    cp ../workspace/$1.xml ./src/chrome/content/rules/
    git add ./src/chrome/content/rules/$1.xml
    git commit -m "Added $1 [$2]"
    git push origin $1
    git checkout master
}

rm $1.xml

python3 ruleset-generator.py -d $1 -n "$2" -v

cat $1.xml
yes_or_no "Does the file $1.xml look good?" && push_to_git