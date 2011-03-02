export HISTFILE=$1
set -o history

sleep 2

history -c
history -r

echo "B: line 1"
echo "B: line 2"
echo "B: line 3"

history -a
history -w
