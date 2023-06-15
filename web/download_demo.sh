#!/bin/bash


SERVER=vm.seitan.rocks
USER=root
DIR=demo_videos

mkdir -p $DIR
scp $USER@$SERVER:~/seitan/*.cast.gz $DIR
