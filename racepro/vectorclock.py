class VectorClock:
    """Classic vector clock"""
    def __init__(self, d=dict()):
        if d and min(d.values()) <= 0:
            raise ValueError('clock values must be positive')
        self._clocks = dict(d)

    def __getitem__(self, pid):
        try:
            return self._clocks[pid]
        except KeyError:
            return 0

    def tick(self, pid):
        vc_new = VectorClock(self._clocks)
        try:
            vc_new._clocks[pid] += 1
        except KeyError:
            vc_new._clocks[pid] = 1
        return vc_new

    def __eq__(self, vc):
        if not isinstance(vc, VectorClock):
            return False
        return self._clocks == vc._clocks

    def merge(self, vc):
        vc_new = VectorClock()
        for pid in set(self._clocks.keys() + vc._clocks.keys()):
            vc_new._clocks[pid] = max([self[pid], vc[pid]])
        return vc_new

    def before(self, vc):
        for pid in set(self._clocks.keys() + vc._clocks.keys()):
            if self[pid] > vc[pid]:
                return False
        return True

    def race(self, vc):
        return not (self.before(vc) or vc.before(self))

    def __str__(self):
        return str(self._clocks)

    def __repr__(self):
        return "VectorClock(%s)" % str(self._clocks)
