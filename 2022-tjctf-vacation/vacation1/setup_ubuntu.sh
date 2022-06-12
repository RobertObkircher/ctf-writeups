# docker run --rm -it -v$PWD:/foo ubuntu:focal-20220404
# cd foo && sh setup_ubuntu.sh

apt-get update
apt-get install vim gdb python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade pwntools

