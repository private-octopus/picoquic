'''
File to plot the output of the dl_throughput experiment
Authors: Milind Kumar V, ChatGPT
'''

import pandas as pd
import numpy as np 
import matplotlib.pyplot as plt 

# Plotting the cpu usage without throughput limit
# folders = ['../cpu_usage/1GB/',
#         '../cpu_usage/5GB/',
#         '../cpu_usage/100MB/'] 

# Plotting the cpu usage with throughput limit of 100 Mbps
folders = ['../cpu_usage/1GB_100Mbps/',
        '../cpu_usage/5GB_100Mbps/',
        '../cpu_usage/100MB_100Mbps/'] 



for folder in folders:
    fig = plt.figure()
    nodes = ["server", "client"]
    for node in nodes:
        # server graph
        dataframes = []
        for i in range(25):
            iter = i + 1
            filename = folder + node + "_usage_" + str(iter) + ".csv"
            # df = pd.read_csv(server_filename) 
            df = pd.read_csv(filename, usecols=[0, 3], header=None, names=['time', 'value'])

            # Convert the 'value' column from a string of format "<integer>%" to an integer
            df['value'] = df['value'].str.rstrip('%').astype(int)

            # Set 'time' as the index
            df.set_index('time', inplace=True)

            # Rename the 'value' column to the file name for clarity
            df.rename(columns={'value': filename}, inplace=True)

            # Append the dataframe to the list
            dataframes.append(df)

        # Combine all dataframes, filling missing values with zeros
        combined_df = pd.concat(dataframes, axis=1).fillna(0)

        # Convert the combined dataframe to a numpy array
        final_array = combined_df.reset_index().to_numpy()
        time = final_array[:,0]
        mean_usage = final_array[:,1:].mean(axis = 1)
        max_usage = final_array[:,1:].max(axis = 1)
        min_usage = final_array[:,1:].min(axis = 1)
        # print(final_array.shape)

        ax = fig.add_subplot(len(nodes),1, nodes.index(node) + 1)
        ax.plot(time, mean_usage)
        ax.fill_between(time, min_usage, max_usage, alpha=0.2)
        ax.set_title(node + " usage")
        ax.grid(True, linestyle='--')
        ax.set_xlabel("time (s)")
        ax.set_ylabel("CPU usage %")
        ax.yaxis.set_ticks(np.arange(0, 100, 10))


    fig.tight_layout(rect=[0, 0.03, 1, 0.95])
    fig.suptitle(folder.strip().split("/")[-2] + " size file transfer", fontsize = 20)
    # plt.xlabel("time (s)")
    # plt.ylabel("CPU usage %")
    # plt.grid()
    fig.savefig(folder + folder.strip().split("/")[-2]+ "_cpu_usage.png")
    fig.savefig(folder + folder.strip().split("/")[-2]+ "_cpu_usage.pdf")



