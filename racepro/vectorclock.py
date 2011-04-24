class VectorClock:
    """Classic vector clock"""
    def __init__(self, d=dict()):
        if d:
            newd = dict()
            for proc, value in d.iteritems():
                if value < 0:
                    raise ValueError('clock values must be non negative')
                if value == 0:
                    continue
                newd[proc] = value
            d = newd
        self._clocks = dict(d)

    def __getitem__(self, proc):
        try:
            return self._clocks[proc]
        except KeyError:
            return 0

    def tick(self, proc):
        vc_new = VectorClock(self._clocks)
        try:
            vc_new._clocks[proc] += 1
        except KeyError:
            vc_new._clocks[proc] = 1
        return vc_new

    def __eq__(self, vc):
        if not isinstance(vc, VectorClock):
            return False
        return self._clocks == vc._clocks

    def merge(self, vc):
        # we can do such things because VectorClock() is immutable
        assert isinstance(vc, VectorClock)
        if not self._clocks:
            return vc
        if not vc._clocks:
            return self

        vc_new = VectorClock(self._clocks)
        for proc, value in vc._clocks.iteritems():
            vc_new._clocks[proc] = max([value, vc_new[proc]])
        return vc_new

    def before(self, vc):
        for proc in set(self._clocks.keys() + vc._clocks.keys()):
            if self[proc] > vc[proc]:
                return False
        return True

    def race(self, vc):
        return not (self.before(vc) or vc.before(self))

    def __str__(self):
        return str(self._clocks)

    def __repr__(self):
        return "VectorClock(%s)" % str(self._clocks)
