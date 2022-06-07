#!/bin/bash

echo "PCAP Parser v 1.0"
echo "by Ujas Dhami (https://github.com/ujasdhami)"

command -v tshark >/dev/null 2>&1 || { printf >&2 "\nTshark is not installed. Use 'sudo apt install -y tshark' for installing it.\nAborting."; exit 1 ; }


printf "\n\n0. Capture and Analyze\n1. Analyze a file"
printf "\n\nYour choice: "
read var

if [[ $var == 0 ]]
then
	printf "\n\nEnter name of the scope (leave no spaces): "
	read scope
	printf "\nEnter number of packets to capture: "
	read packets
	cd scopes
	mkdir $scope.pcap
	cd $scope
	tshark -c $packets -w $scope.pcap
	sleep 2
	printf "\n+ Extracting IP Addresses..."
	tshark -r $scope.pcap -T fields -e ip.src -e ip.dst | tr "\t" "\n" | sort | uniq > IP_addr.csv
	printf "\n+ Extracting MAC Addresses..."
	tshark -r $scope.pcap -T fields -e eth.src -e eth.dst | tr "\t" "\n" | sort | uniq > MAC_addr.csv
	printf "\n+ Extracting TCP data..."
	tshark -r $scope.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -Y tcp > tcp_src_dst_ports.csv
	printf "\n+ Extracting UDP data..."
	tshark -r $scope.pcap -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -Y udp > udp_src_dst_ports.csv
	printf "\n+ Extracting Unique TCP data..."
	tshark -r $scope.pcap -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -Y tcp | sort -u > unique_tcp_src_dst_ports.csv
	printf "\n+ Extracting Unique UDP data..."
	tshark -r $scope.pcap -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -Y udp | sort -u > unique_udp_src_dst_ports.csv
	printf "\n+ Extracting TLS traffic..."
	tshark -r $scope.pcap -Y tls | sort -u > tls.csv
	printf "\n+ Extracting FTP traffic..."
	tshark -r $scope.pcap -Y ftp | sort -u > ftp.csv
	printf "\n+ Extracting HTTP traffic..."
	tshark -r $scope.pcap -Y http | sort -u > http.csv
	printf "\n+ Extracting POP3 traffic..."
	tshark -r $scope.pcap -Y pop | sort -u > pop.csv
	printf "\n+ Extracting SMTP traffic..."
	tshark -r $scope.pcap -Y smtp | sort -u > smtp.csv
	printf "\n+ Extracting ICMP traffic..."
	tshark -r $scope.pcap -Y icmp | sort -u > icmp.csv
	printf "\n+ Extracting SSH traffic..."
	tshark -r $scope.pcap -Y ssh | sort -u > ssh.csv
	sleep 3s
	printf "\n\nParsing complete. Check SCOPE name under 'scopes' directory."
elif [[ $var == 1 ]]
then
	printf "\n\nEnter name of the file (leave no spaces): "
	read scope
	printf "\nEnter full path (including file name): "
	read path
	cd scopes
	mkdir $scope
	cd $scope
	cp $path .
	sleep 2
	printf "\n+ Extracting IP Addresses..." 
	tshark -r $scope -T fields -e ip.src -e ip.dst | tr "\t" "\n" | sort | uniq > IP_addr.csv
	printf "\n+ Extracting MAC Addresses..."
	tshark -r $scope -T fields -e eth.src -e eth.dst | tr "\t" "\n" | sort | uniq > MAC_addr.csv
	printf "\n+ Extracting TCP data..."
	tshark -r $scope -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -Y tcp > tcp_src_dst_ports.csv
	printf "\n+ Extracting UDP data..."
	tshark -r $scope -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -Y udp > udp_src_dst_ports.csv
	printf "\n+ Extracting Unique TCP data..."
	tshark -r $scope -T fields -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -Y tcp | sort -u > unique_tcp_src_dst_ports.csv
	printf "\n+ Extracting Unique UDP data..."
	tshark -r $scope -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -Y udp | sort -u > unique_udp_src_dst_ports.csv
	printf "\n+ Extracting TLS traffic..."
	tshark -r $scope -Y tls | sort -u > tls.csv
	printf "\n+ Extracting FTP traffic..."
	tshark -r $scope -Y ftp | sort -u > ftp.csv
	printf "\n+ Extracting HTTP traffic..."
	tshark -r $scope -Y http | sort -u > http.csv
	printf "\n+ Extracting POP3 traffic..."
	tshark -r $scope -Y pop | sort -u > pop.csv
	printf "\n+ Extracting SMTP traffic..."
	tshark -r $scope -Y smtp | sort -u > smtp.csv
	printf "\n+ Extracting ICMP traffic..."
	tshark -r $scope -Y icmp | sort -u > icmp.csv
	printf "\n+ Extracting SSH traffic..."
	tshark -r $scope -Y ssh | sort -u > ssh.csv
	sleep 3s
	printf "\n\nParsing complete. Check SCOPE name under 'scopes' directory."
else
	printf "\n\nInvalid option. Quitting."
fi
	