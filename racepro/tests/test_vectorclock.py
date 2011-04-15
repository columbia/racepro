from nose.tools import *
from racepro import VectorClock

def test_init():
    vc = VectorClock()
    assert_equal(vc[0], 0)
    assert_equal(vc[1], 0)
    assert_equal(vc[2], 0)

def test_init_dict():
    vc = VectorClock({1: 2, 2: 4, 3: 5})
    assert_equal(vc[0], 0)
    assert_equal(vc[1], 2)
    assert_equal(vc[2], 4)
    assert_equal(vc[3], 5)

@raises(ValueError)
def test_init_dict_inval1():
    VectorClock({1:0})

@raises(ValueError)
def test_init_dict_inval2():
    VectorClock({1:-1})

def test_tick():
    vc1 = VectorClock()
    vc2 = vc1.tick(1)
    assert_not_equal(vc1[1], vc2[1])
    assert_equal(vc2[1], 1)
    assert_equal(vc2[2], 0)

    vc3 = vc2.tick(1)
    assert_equal(vc3[1], 2)

def test_before():
    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({     2:2, 3:3})
    assert_false(vc1.before(vc2))

    vc1 = VectorClock({2:2})
    assert_true(vc1.before(vc1))

    vc1 = VectorClock({2:1})
    vc2 = VectorClock({2:2})
    assert_true(vc1.before(vc2))
    assert_false(vc2.before(vc1))

    vc1 = VectorClock({2:1})
    vc2 = VectorClock({2:2, 3:3})
    assert_true(vc1.before(vc2))

    vc1 = VectorClock({2:2})
    vc2 = VectorClock({2:2, 3:3})
    assert_true(vc1.before(vc2))

    vc1 = VectorClock({2:3})
    vc2 = VectorClock({2:2, 3:3})
    assert_false(vc1.before(vc2))

    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({     2:3})
    assert_false(vc1.before(vc2))

    vc1 = VectorClock()
    vc2 = VectorClock({1:1})
    assert_true(vc1.before(vc2))

    vc1 = VectorClock()
    vc2 = VectorClock({1:1})
    assert_true(vc1.before(vc2))
    assert_false(vc2.before(vc1))

    vc1 = VectorClock()
    assert_true(vc1.before(vc1))

def test_race():
    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({     2:2, 3:3})
    assert_true(vc1.race(vc2))

    vc1 = VectorClock({2:1})
    vc2 = VectorClock({2:2})
    assert_false(vc1.race(vc2))
    assert_false(vc2.race(vc1))

    vc1 = VectorClock({2:1})
    vc2 = VectorClock({2:2, 3:3})
    assert_false(vc1.race(vc2))

    vc1 = VectorClock({2:2})
    vc2 = VectorClock({2:2, 3:3})
    assert_false(vc1.race(vc2))

    vc1 = VectorClock({2:3})
    vc2 = VectorClock({2:2, 3:3})
    assert_true(vc1.race(vc2))

    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({     2:3})
    assert_true(vc1.race(vc2))

    vc1 = VectorClock()
    vc2 = VectorClock({1:1})
    assert_false(vc1.race(vc2))
    assert_false(vc2.race(vc1))

    vc1 = VectorClock()
    assert_false(vc1.race(vc1))

def test_equal():
    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({1:1, 2:2})
    assert_equal(vc1, vc1)
    assert_equal(vc1, vc2)
    assert_equal(vc2, vc2)

    vc1 = VectorClock({1:2})
    vc2 = VectorClock({1:1})
    assert_not_equal(vc1, vc2)
    assert_true(vc1 != vc2)
    assert_false(vc1 == vc2)

    assert_not_equal(vc1, None)
    assert_not_equal(vc1, 1)
    assert_not_equal(vc1, {1:2})

def test_merge():
    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock()
    assert_equal(vc1.merge(vc2), vc1)

    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({1:1, 2:3})
    assert_equal(vc1.merge(vc2), vc2)

    vc1 = VectorClock({1:1, 2:2})
    vc2 = VectorClock({     2:3, 3:3})
    assert_equal(vc1.merge(vc2), VectorClock({1:1, 2:3, 3:3}))

def test_str():
    vc = VectorClock({1:1, 2:2})
    assert_equal(str(vc), str({1:1, 2:2}))

def test_repr():
    vc = VectorClock({1:1, 2:2})
    assert_true('VectorClock' in repr(vc))
