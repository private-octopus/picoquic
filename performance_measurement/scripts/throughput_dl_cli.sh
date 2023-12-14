# Script to run the client n_iterations times for a given file 
# (file_request) and output the results in a csv at a specified location

#!/bin/bash

# Define the number of iterations and the file request
n_iterations=$1
file_request=$2
output_file=$3

# Name of the output CSV file


# Check if the arguments are not empty and if the first argument is a number
if ! [[ "$n_iterations" =~ ^[0-9]+$ ]] || [ -z "$file_request" ] || [ -z "$output_file" ]; then
    echo "Usage: $0 <number_of_iterations> <file_request> <output_file>"
    exit 1
fi

# Write the header to the CSV file
echo "Iteration,Value" > "$output_file"

# Loop for the specified number of iterations
for ((i=1; i<=n_iterations; i++))
do
    # Run the command with the file request and capture the output
    output=$(../../picoquicdemo -n test -o ../../client_files/. 0.0.0.0 4433 "$file_request")

    # Extract the value
    value=$(echo "$output" | grep -o "Received .* Mbps" | awk '{print $(NF-1)}')

    # Check if the value was successfully extracted
    if [ -z "$value" ]; then
        echo "Failed to extract value on iteration $i"
    else
        # Write the iteration number and the extracted value to the CSV file
        echo "$i,$value" >> "$output_file"
    fi
done

echo "Results written to $output_file"
