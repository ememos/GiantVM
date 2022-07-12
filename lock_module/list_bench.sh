LOCK_PATH=/sys/kernel/debug/lock_benchmark
CPU=$1
BENCH=$2
DELAY=$3

echo $CPU > $LOCK_PATH/cpu
echo $BENCH > $LOCK_PATH/nr_bench
echo $DELAY > $LOCK_PATH/delay

dmesg -c > /dev/null
echo 3 > $LOCK_PATH/trigger
READY=$(cat $LOCK_PATH/ready)
while [ "$READY" -eq 0 ]
do
	sleep 1
	READY=$(cat $LOCK_PATH/ready)
done

echo 4 > $LOCK_PATH/trigger
READY=$(cat $LOCK_PATH/ready)
while [ "$READY" -eq 0 ]
do
	sleep 1
	READY=$(cat $LOCK_PATH/ready)
done

python3 parse_dmesg_list.py $1 >> result

