LOCK_PATH=/sys/kernel/debug/lock_benchmark
CPU=$1

echo $CPU > $LOCK_PATH/cpu
dmesg -c > /dev/null
echo 1 > $LOCK_PATH/trigger
sleep 8
echo 2 > $LOCK_PATH/trigger
sleep 8
echo "CPU:$CPU" >> result
python3 parse_dmesg.py $1 >> result

