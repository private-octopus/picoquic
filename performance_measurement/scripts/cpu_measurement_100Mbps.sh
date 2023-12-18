# Script to produce cpu_usage measurements when a 100 Mbps 
# throughput limit is set using tc on localhost

./cpu_usage.sh 25 transfer_test_100M.htm performance_measurement/cpu_usage/100MB_100Mbps/
./cpu_usage.sh 25 transfer_test_1G.htm performance_measurement/cpu_usage/1GB_100Mbps/
./cpu_usage.sh 25 transfer_test_5G.htm performance_measurement/cpu_usage/5GB_100Mbps/
