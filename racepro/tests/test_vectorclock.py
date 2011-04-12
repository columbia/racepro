from nose.tools import *
from racepro import VectorClock

def test_init():
    vc = VectorClock(pid=1)
    assert_equal(vc[1], 1)

    vc = VectorClock(2)
    assert_equal(vc[2], 1)

def test_tick():
    vc = VectorClock(1)
    vc.tick(1)
    assert_equal(vc[1], 2)
