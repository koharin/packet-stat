all:packet-stat

packet-stat: header.h packet-stat.cpp
	g++ -o packet-stat packet-stat.cpp -lpcap

clean:
	rm packet-stat
