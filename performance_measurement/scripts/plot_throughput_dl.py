'''
File to plot the output of the dl_throughput experiment
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

files = ['../throughput_dl/transfer_test_100MB_100Mbps_results.csv',
        '../throughput_dl/transfer_test_1GB_100Mbps_results.csv',
        '../throughput_dl/transfer_test_5GB_100Mbps_results.csv']

output_file_name_png = "../throughput_dl/mean_throughputs_100Mbps.png"
output_file_name_pdf = "../throughput_dl/mean_throughputs_100Mbps.pdf"



mean_throughputs = []

for i in range(3):
    file_name = files[i]
    df = pd.read_csv(file_name)
    mean = df["Value"].mean()
    mean_throughputs.append(mean)

    # mean_data = data.mean(axis = 1)
    # print(mean_data)

file_sizes = ["100 MB", "1 GB", "5 GB"]


plt.figure(figsize = (10,8))
plt.xlabel("File size", fontsize = 23)
plt.ylabel("Mean (25 iterations) DL throughput (Mbps)", fontsize = 20)
plt.title("Throughput measurements", fontsize = 23)

plt.xticks(fontsize=20)
plt.yticks(fontsize=20)

plt.bar(file_sizes, mean_throughputs, color ='maroon', 
        width = 0.4)


plt.savefig(output_file_name_pdf)
plt.savefig(output_file_name_png)