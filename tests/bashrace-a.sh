export HISTFILE=$1
set -o history

sleep 1

history -c
history -r

echo "A: line 1"
echo "A: line 2"
echo "A: line 3"

history -a
history -w
