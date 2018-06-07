set -e
sudo apt-get install python-docutils
sudo apt-get install libpcap0.8-dev libpcre3-dev
git clone git://github.com/gamelinux/prads.git
cd prads
make
sudo make install
