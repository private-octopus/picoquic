# Script to run the cpu measurement script with the tc rule active for 100 Mbps and 
# with http server client using a TCP socket

./cpu_usage_tcp.sh 25 transfer_test_100M.htm ../performance_measurement/cpu_usage/100MB_100Mbps_TCP/
./cpu_usage_tcp.sh 25 transfer_test_1G.htm ../performance_measurement/cpu_usage/1GB_100Mbps_TCP/
./cpu_usage_tcp.sh 25 transfer_test_5G.htm ../performance_measurement/cpu_usage/5GB_100Mbps_TCP/
