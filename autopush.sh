#!/bin/bash

rm $1.xml

python3 ruleset-generator.py -d $1 -n "$2" -v

cat $1.xml
echo "Does the file $1.xml look good? Ctrl+C if not."
read test1
read test2

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