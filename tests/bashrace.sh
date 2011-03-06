#!/bin/bash --norc

hist=/tmp/bashrace.history
export HISTFILE=$hist

rm -f $hist
touch $hist
echo "common line" > $hist

mkdir -p /tmp/bashrace.tmp/a
mkdir -p /tmp/bashrace.tmp/b

bash --norc `dirname $0`/bashrace-a.sh $hist >& /tmp/bashrace.tmp/a/out &
bash --norc `dirname $0`/bashrace-b.sh $hist >& /tmp/bashrace.tmp/b/out &

wait
wait

history -c
history -r

a=`history | grep B | wc`
b=`history | grep A | wc`

rm -f /tmp/bashrace.out
echo "A lines: $a" > /tmp/bashrace.out
echo "B lines: $b" >> /tmp/bashrace.out

exit 0

