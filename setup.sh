#!/bin/bash
rm subbrute -rf
git submodule update --recursive --remote
sudo pip3 install -r requirements.txt
sudo pip3 install -r requirements.txt --upgrade
cd Sublist3r
#sudo pip3 install -r requirements.txt
echo "" > __init__.py
cp subbrute ../subbrute -r