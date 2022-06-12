#!/bin/sh

docker build -t vacation2 .

rm -rf docker
mkdir docker
cd docker

C=$(docker container create vacation2:latest)

echo $C
docker export -o x.tar $C
docker container rm $C

tar -xf x.tar
rm x.tar
