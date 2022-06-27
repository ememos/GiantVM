LOCK_PATH=/sys/kernel/debug/lock_benchmark
CPU=$1

echo $CPU > $LOCK_PATH/cpu
dmesg -c > /dev/null
echo 1 > $LOCK_PATH/trigger
READY=$(cat $LOCK_PATH/ready)
while [ "$READY" -eq 0 ]
do
	sleep 1
	READY=$(cat $LOCK_PATH/ready)
done

echo 2 > $LOCK_PATH/trigger
READY=$(cat $LOCK_PATH/ready)
while [ "$READY" -eq 0 ]
do
	sleep 1
	READY=$(cat $LOCK_PATH/ready)
done

echo "CPU:$CPU" >> result
python3 parse_dmesg.py $1 >> result

