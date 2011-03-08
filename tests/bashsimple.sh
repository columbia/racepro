#!/bin/bash

echo "test1" > /tmp/test1 &
echo "test2" > /tmp/test1 &
echo "test3" > /tmp/test1 &
echo "test4" > /tmp/test1 &
echo "test5" > /tmp/test1 &
echo "test6" > /tmp/test1 &

wait
wait
wait
wait
wait
wait