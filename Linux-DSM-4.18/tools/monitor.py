import time
import errno
import os
from collections import defaultdict

PAGE_MASK = 0xFFFFFFFFFFFFF000
FILTER = "W" 
PERIOD = 50
CR3_INCLUDE_FILTER = []
CR3_EXCLUDE_FILTER = [] #[0x7720a000, 0x231fe0000, 0x23183c000, 0x23183d000]

end_time = time.time() + PERIOD
histogram = defaultdict(int)
keep_watch = True
s_timestamp = -1
e_timestamp = -1

def parse_line(line):
    items = l.split(",")
    timestamp = int(items[2])/1000000
    vcpu = items[3].split("[Monitor] VCPU:")[-1]
    gva = int(items[4].split(" GVA:")[-1], 16) & PAGE_MASK
    gpa = int(items[5].split(" GPA:")[-1], 16) & PAGE_MASK
    rip = int(items[6].split(" RIP:")[-1], 16)
    cr3 = int(items[7].split(" CR3: ")[-1], 16) & PAGE_MASK
    flag = items[8].split(" Flag:")[-1].strip()
    return timestamp, vcpu, gva, gpa, rip, cr3, flag

while keep_watch:
    with open("/dev/kmsg", "r") as kmsg:
        while True:
            if end_time < time.time():
                keep_watch = False
                break
            try:
                l = kmsg.readline()
                if "[Monitor]" not in l:
                    continue
                timestamp, vcpu, gva, gpa, rip, cr3, flag = parse_line(l)
                if FILTER not in flag:
                    continue
                # CR3 Filter apply
                if CR3_INCLUDE_FILTER and cr3 not in CR3_INCLUDE_FILTER:
                    continue
                if cr3 in CR3_EXCLUDE_FILTER:
                    continue

                if s_timestamp == -1:
                    s_timestamp = timestamp
                e_timestamp = timestamp
                histogram[rip] += 1
                print("%0.6f %s %016x %016x %016x %016x" % (timestamp, vcpu, gva, gpa, rip, cr3), flag)
            except IOError as e:
                if e.errno == errno.EPIPE:
                    continue
                raise e 
total = 0
gap = e_timestamp - s_timestamp
for key, value in histogram.items():
    #histogram[key] /= gap
    total += histogram[key]

s = sorted(histogram, key=histogram.get)
for key in s:
    value = histogram[key]
    if value < 10:
        continue
    print("RIP:%016x Miss: %d" % (key, value))
print("Total %d" % total)
