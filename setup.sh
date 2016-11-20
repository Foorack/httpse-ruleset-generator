#!/bin/bash
rm subbrute -rf
git submodule update --init
git submodule update --recursive --remote
easy_install pyOpenSSL && easy_install ndg-httpsclient
sudo pip3 install -r requirements.txt
sudo pip3 install -r requirements.txt --upgrade
cd Sublist3r
#sudo pip3 install -r requirements.txt
echo "" > __init__.py
cp subbrute ../subbrute -r