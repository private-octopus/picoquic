'''
File to plot the output of the dl_latency experiment
Authors: Milind Kumar V
'''

import pandas as pd
import numpy as np 
import matplotlib.pyplot as plt 


# files = ['../throughput_dl/transfer_test_100M_results.csv',
#         '../throughput_dl/transfet_test_1G_results.csv',
#         '../throughput_dl/transfet_test_5G_results.csv']

# output_file_name_png = "../throughput_dl/mean_throughputs.png"
# output_file_name_pdf = "../throughput_dl/mean_throughputs.pdf"

files = ['../latency_dl/transfer_test_1B_results.csv',
         '../latency_dl/transfer_test_10B_results.csv',
         '../latency_dl/transfer_test_100B_results.csv',
         '../latency_dl/transfer_test_1KB_results.csv',
         '../latency_dl/transfer_test_10KB_results.csv',
         '../latency_dl/transfer_test_100KB_results.csv',
         '../latency_dl/transfer_test_1MB_results.csv',
        ]

output_file_name_png = "../latency_dl/mean_latencies_noTC.png"
output_file_name_pdf = "../latency_dl/mean_latencies_noTC.pdf"



mean_throughputs = []
file_sizes = ["1 B", "10 B", "100 B", "1 KB", "10 KB", "100 KB", "1 MB"]

for i in range(len(file_sizes)):
    file_name = files[i]
    df = pd.read_csv(file_name)
    mean = df["Value"].mean()
    mean_throughputs.append(1000*mean)

    # mean_data = data.mean(axis = 1)
    # print(mean_data)




plt.figure(figsize = (10,8))
plt.xlabel("File (message) size", fontsize = 23)
plt.ylabel("Mean (100 iterations) DL latency (ms)", fontsize = 20)
plt.title("Latency measurements", fontsize = 23)


plt.xticks(fontsize=20)
plt.yticks(fontsize=20)

plt.bar(file_sizes, mean_throughputs, color ='blue', 
        width = 0.6)
# plt.grid(True)

plt.savefig(output_file_name_pdf)
plt.savefig(output_file_name_png)