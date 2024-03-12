# Performance measurement for Picoquic and TCP code

First, set up picoquic as per the original instructions provided by Cloudflare.

## TC rules 

- Checking TC rule

```
tc -s qdisc show dev lo
```

- Removing TC rule

```
sudo tc qdisc del dev lo root 2>/dev/null
```

- Adding a 100 Mbps TC rule

```
sudo tc qdisc add dev lo root handle 1: tbf rate 100Mbit burst 2mbit latency 40ms
```

- Resources for setting up TC rule
    - [Link 1](https://chat.openai.com/share/8f42f25d-8000-48f4-aa2d-ee6276c02fb1)
    - [Link 2](https://unix.stackexchange.com/a/100797)
    - Checking HZ on system
    ```
    egrep '^CONFIG_HZ_[0-9]+' /boot/config-`uname -r`
    ```

## Picoquic

### Create files to be transferred

- Below experiments are done using large file transfer. The files can be created using 

```
dd if=/dev/zero of=transfer_test_1G.htm bs=1G count=1
```

(or a .txt file according to preference).

**Create a directory named ```server_files``` in the ```picoquic``` root directory
and create this file there,** i.e, it should have the path 

```
picoquic/server_files/transfer_test_1G.htm
```

- Similarly, create a ```client_files/``` directory in the ```picoquic``` root directory.

### Throughput measurements

- These are based on the ```picoquicdemo``` code.  

- Create a ```throughput_dl``` directory in ```picoquic/performance_measurement```.
This is where your resulting csv files will go.

#### Experiment

- Start the server from the ```picoquic``` directory using 
```
./picoquicdemo -w server_files/ -p 4433
```
- Run the ```throughput_dl_cli.sh``` script from  ```picoquic/performance_measurement/scripts``` as 

```
./throughput_dl_cli.sh 25 transfer_test_1G.htm ../throughput_dl/transfer_test_1G_results.csv
```

This will run the client 25 times, each time transferring transfer_test_1G.htm from ```server_files```
to ```client files``` and then store the average throughput in ```../throughput_dl/transfer_test_1G_results.csv```.

- Then from ```picoquic/performance_measurements/scripts```, run 

```
python3 plot_throughput_dl.py
```
The ```files```, ```output_file_name_png``` and ```output_file_name_pdf``` variables 
have to be changed appropriately to produce the plot. This will create a bar graph 
with the throughput.

- Repeat for different file sizes as you please.

- Set the TC rule and repeat the experiement. Change the file names and file paths accordingly.

- Stop the server after the experiement is done.

### CPU usage measurement

- This is also based on the picoquicdemo code
- Make sure that no picoquic server or client is running and that the file structure is as 
described previously.
- Create a nested directory named ```cpu_usage/1GB``` in ```picoquic/performance_measurement```
- From the ```scripts``` directory, run

```
./cpu_usage.sh 25 transfer_test_1G.htm performance_measurement/cpu_usage/1GB/
```

This will do the following 25 times
    - start the server and start measuring cpu usage
    - start the client and start measuring cpu usage
    - record those in ```server_usage_<iter_num>.csv``` and ```client_usage_<iter_num>.csv``` files
    in ```performance_measurement/cpu_usage/1GB/``` at intervals of 1s 
        - **Note**: this 1s is hard coded both into the top command how the time measurement is 
        recorded using a counter
    - close client and monitor process
    - wait and then close server and monitor process (not necessarily in that order)

- From ```picoquic/performance_measurement/scripts``` run

```
python3 plot_cpu_usage.py
```

The ```folders``` and ```n_iterations_used``` variables need to be set correctly. ```n_iterations_used```
restricts how many iterations of the experiment are used for plotting. The ```yrange``` variable needs
to be set depending on what the range of CPU usage variation is going to be.

- Repeat experiment for other file sizes or with TC rules set.

### Latency measurement 

- Switch to the ```latency_measurement``` branch.
- These measurements are done using the sample code instead of picoquicdemo
- The experimental setup invovles some hardcoding and global variables that need
to be set beforehand
- Determine the message size: this will be the size of the file that is being 
transferred. Create these files in the ```picoquic/server_files``` directory. Then create a 
symlink to it in ```picoquic/sample/``` so that ```server_files``` is available as a
directory in ```picoquic_sample``` (alternately, you can just create those files/that folder
in the ```sample``` directory directly)
- Open the ```picoquic/sample/``` directory. 
- Create a ```temp/``` directory.
- Follow the instructions in the ```sample``` directory to create the necessary keys and certificates.
This should involve the following steps
    - ```openssl req -x509 -newkey rsa:2048 -days 365 -keyout ca-key.pem -out ca-cert.pem```
    - ```openssl req -newkey rsa:2048 -keyout server-key.pem -out server-req.pem```
    - Set the passphrase to ```1234``` and hit ```Enter``` for the other fields. This creates ```server-key.pem``` and ```server-req.pem```.

#### Experiment

- Now set the global variables in ```sample_client.c```
```
int transfer_filesize = 10240;
int timestamp_filesize = 10240;
```
These should be set to the size of the file you are transferring (obtain using ```ls -al```). Sizes
can be varied from 1 B, 10 B, 10 KB, ..., 1 MB, etc. **Note that both the variables should be set
to the same value**.

- Then set the global variables in ```sample_server.c```
```
int n_iterations = 25;
int n_next = 25;
```

Set ```n_iterations``` to how many times the message should be sent to client in each connection.
Set ```n_next``` to the same value.

- From ```picoquic``` run

```
make picoquic_sample
```

- From ```picoquic/sample```, run 
```
../picoquic_sample server 4433 ./ca-cert.pem ./server-key.pem ./server_files
``` 

and also (in another terminal)

```
../picoquic_sample client localhost 4433 ./temp <filename>
```

- This will produce two files ```client_timestamps.csv``` and ```server_timestamps.csv``` in 
```picoquic/sample```. Each should have ```n_iterations``` number of entries. The server timestamps 
are recorded every time the message is begun to be sent anew (i.e per iteration). The client timestamp
is recorded everytime ```transfer_filesize``` number of bytes are received

- Make sure to restart the server between successive runs of the experiment. The use of global 
variables messes up the experiment if the server is not restarted between successive trials.

- From ```picoquic/sample``` run 

```
python3 latency_measurement.py
```

which should print out the mean latency for each message.

- Repeat with different file sizes.



## TCP code


The code is present in ```picoquic/mp1```. It can be compiled by running ```make``` from
the same directory.

### Throughputs

- This was done in a rather ad hoc way by using the latency measurements, measuring average latency
and then dividing file size by that. Fixing this is a **TODO**.

### CPU measurements

The method is very similar to that of Picoquic. 

- Use the ```master branch```.
- Make sure that no picoquic server or client is running
- Create a nested directory named ```cpu_usage/1GB_TCP``` in ```picoquic/performance_measurement```
- From the ```scripts``` directory, run

```
./cpu_usage_tcp.sh 25 transfer_test_1G.htm ../performance_measurement/cpu_usage/1GB_TCP/
```
This will do the following 25 times
    - start the server and start measuring cpu usage
    - start the client and start measuring cpu usage
    - record those in ```server_usage_<iter_num>.csv``` and ```client_usage_<iter_num>.csv``` files
    in ```performance_measurement/cpu_usage/1GB/``` at intervals of 1s 
        - **Note**: this 1s is hard coded both into the top command how the time measurement is 
        recorded using a counter
    - close client and monitor process
    - wait and then close server and monitor process (not necessarily in that order). Note that the
    server dies immediately after sending the file once and doesn't produce any child processes using 
    fork. This was done for easier monitoring with top.

- From ```picoquic/performance_measurements/scripts``` run

```
python3 plot_cpu_usage.py
```

The ```folders``` and ```n_iterations_used``` variables need to be set correctly. ```n_iterations_used```
restricts how many iterations of the experiment are used for plotting. The ```yrange``` variable needs
to be set depending on what the range of CPU usage variation is going to be.

- Repeat experiment for other file sizes or with TC rules set.

### Latency measurement 

- Switch to the ```latency_measurement``` branch.
- Create a directory named ```latency_dl``` in ```picoquic/performance_measurement```
- Create a directory named ```server_files``` in ```picoquic/mp1``` and populate it with files
whose size corresponds to the message size (as described for picoquic).
- Run the server as 

```
./http_server 5000 ../performance_measurement/latency_dl/TCPserver_1MB.csv 25
```

and the client as 

```
./http_client http://localhost:5000/server_files/transfer_test_1M.htm ../performance_measurement/latency_dl/TCPclient_1MB.csv <filesize>
```

where ```filesize``` should be set to the size of the file you are transferring (obtain using ```ls -al```). Sizes
can be varied from 1 B, 10 B, 10 KB, ..., 1 MB, etc.

- This will produce two files ```TCPserver_1MB.csv``` and ```TCPclient_1MB.csv``` in 
```picoquic/performance_measurement/latency_dl```. Each should have ```n_iterations = 25``` number of entries. The server timestamps are recorded every time the message is begun to be sent anew (i.e per iteration). The client timestamp is recorded everytime ```filesize``` number of bytes are received.

- From ```picoquic/performance_measurement/scripts/``` run

```
python3 tcp_latency_average.py
```

- This should print the average latency of sending a message.
