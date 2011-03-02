#!/bin/bash --norc

echo "DEBUG starting"

hist=/tmp/bashrace.history

rm -f $hist
touch $hist
echo "common line" > $hist

bash --norc `dirname $0`/bashrace-a.sh $hist &
bash --norc `dirname $0`/bashrace-b.sh $hist &

wait
wait

export HISTFILE=$hist
history -c
history -r

a=`history | grep B | wc`
b=`history | grep A | wc`

rm -f /tmp/bashrace.out
echo "A lines: $a" > /tmp/bashrace.out
echo "B lines: $b" >> /tmp/bashrace.out

exit 0

