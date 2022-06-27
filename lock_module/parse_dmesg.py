import subprocess
import psutil
import sys
import os
import math
import matplotlib.pyplot as plt
import numpy as np

clk = 1 / (psutil.cpu_freq().current / (1000*1000))
print(clk)
cc_lock = {"name":"cc_lock  ", "nr":0, "time":list(), "color":"r"}
spin_lock = {"name":"spin_lock", "nr":0, "time":list(), "color":"b"}

def print_stat(target):
    avg = sum(target["time"])*1000 / target["nr"]
    var = sum([(avg-i)**2 for i in target["time"]]) / len(target["time"])
    d = np.array(target["time"])
    plt.hist(d, bins=200, alpha=0.7, histtype='step', color=target["color"], label=target["name"])
    #print("[{0}] average clock: {1:15.5f} std: {2:15.5f}, nr: {3}".format(target["name"],
    #        avg, math.sqrt(var), target["nr"]))
    print(avg, math.sqrt(var),)
    return avg

if __name__ == "__main__":
    lines = subprocess.check_output(["sudo", "dmesg"]).decode()
    lines = lines.split("\n")
    for line in lines:
        if "cc-lock" in line:
            target = cc_lock
        elif "spinlock" in line:
            target = spin_lock
        else:
            target = None
        if target is None:
            continue

        target["nr"] += 1000
        target["time"].append(int(line[line.rfind("[")+1:-1])/(clk))

    cc_avg = print_stat(cc_lock)
    spin_avg = print_stat(spin_lock)
    plt.xlim(0,1000*10)
    plt.xticks(np.arange(0, 1000*10, 1000))
    plt.minorticks_on()
    plt.ylabel("instuction")
    plt.xlabel("clock")
    plt.legend(loc='upper right')
    plt.title("CPU: {0}".format(sys.argv[1]))
    plt.savefig("{0}.png".format(sys.argv[1]))

    print("improvment: {0:10.5f}%".format((spin_avg-cc_avg)/spin_avg*100))

