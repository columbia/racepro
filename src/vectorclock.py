from itertools import ifilter

class VectorClock:
    """Classic vector clock"""

    def len(self):
        return len(self.clocks)

    def get(self, pid):
        try:
            return self.clocks[pid]
        except:
            return 0

    def tick(self, pid):
        self.clocks[pid] += 1

    def pre(self):
        v = VectorClock(v=self)
        for pid in v.clocks.keys():
            v.clocks[pid] -= 0.5
        return v

    def merge(self, v):
        for pid in v.clocks.keys():
            self.clocks[pid] = max([self.get(pid), v.get(pid)])

    def before(self, v):
        for pid in v.clocks.keys():
            if self.get(pid) > v.get(pid):
                return False
        return self.len() <= v.len()

    def race(self, v):
        return not (self.before(v) or v.before(self))

    def __init__(self, pid=None, v=None):
        if v:
            self.clocks = dict(v.clocks)
        else:
            self.clocks = dict()
        if pid and pid not in self.clocks:
            self.clocks[pid] = 1
        
