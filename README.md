#faketraffic generator
./udpgencl -s source ipd address -d destination ip address -p port -b bandwidth in Mb -l pkacketlen -v verbose
for example
./udpgencl -s 202.11.11.11 -d 202.96.0.133 -p 80 -b 100 -l 1000 -v

