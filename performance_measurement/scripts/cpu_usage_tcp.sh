#!/bin/bash

# Script to measure CPU performance using the top command
# Run as ./cpu_usage_tcp.sh n_iterations file_to_request_from_server output_folder
# It starts a server, then a client and monitors cpu usage of both until the client 
# dies. Saves (time, cpu usage) information as (client/server)_use_iternum.csv in 
# output_folder.
# Authors: Milind Kumar V, ChatGPT

 

n_iterations=$1
file_request=$2
output_folder=$3

# server only works from root directory
cd ../../mp1

for ((i=1; i<=n_iterations; i++))
do
    echo -e "Iteration: $i \n"

    # Start the server and get its PID
    ./http_server 5000 &
    SERVER_PID=$!
    echo "Server started with PID: $SERVER_PID"

    # Function to monitor CPU usage
    monitor_cpu_usage() {
        local process_name=$1
        local output_file=$2
        local process_pid=$3
        
        
        # Loop to monitor CPU usage
        # while true; do
        #     # echo $process_pid
        #     if [ -z "$process_pid" ]; then
        #         echo "Process $process_name ended."
        #         break
        #     fi
            # echo "$(date '+%Y-%m-%d %H:%M:%S'), $(ps -p $process_pid -o %cpu | tail -n 1)" >> "$output_file"
        
        # TODO: Fix the -d and counter intervals by adding a new variable
        top -b -d 1 -p $process_pid | awk \
            -v cpuLog="$output_file" -v pid="$process_pid" -v pname="$process_name" '
            BEGIN {counter = 0}
            $1+0>0 {printf "%d, %s[%s],CPU Usage,%d%%\n", \
                    counter, pname, pid, $9 > cpuLog
                    fflush(cpuLog)
                    counter += 1
                    }'
        
        #     sleep 1
        # done
    }

    # Start monitoring server CPU usage
    monitor_cpu_usage "http_server" "${output_folder}server_usage_${i}.csv" $SERVER_PID & 
    MONITOR_SERVER_PID=$!
    echo "Started monitoring server CPU usage."

    sleep 1

    # Start the client
    ./http_client http://localhost:5000/server_files/$file_request &
    CLIENT_PID=$!
    echo "Client started with PID: $CLIENT_PID"


    # # Start monitoring client CPU usage
    monitor_cpu_usage "http_client" "${output_folder}client_usage_${i}.csv" $CLIENT_PID & 
    MONITOR_CLIENT_PID=$!
    echo "Started monitoring client CPU usage."

    # # Wait for the client to finish
    wait $CLIENT_PID
    echo "Client process finished."

    # # sleep 45
    # Kill the client CPU usage monitoring
    kill $MONITOR_CLIENT_PID
    echo "Stopped monitoring client CPU usage."

    # Wait for 5 seconds
    sleep 5
    # # Kill the server CPU usage monitoring
    kill $MONITOR_SERVER_PID
    echo "Stopped monitoring server CPU usage."

    # # Kill the server
    wait $SERVER_PID
    echo -e "Server process finished \n"
done

echo -e "Experiment completed!! \n \n"