from itertools import ifilter

class VectorClock:
    """Classic vector clock"""

    def len(self):
        return len(self.clocks)

    def get(self, pid):
        try:
            return self.clocks[pid]
        except:
            self.clocks[pid] = 0
            return 0

    def tick(self, pid):
        self.clocks[pid] += 1

    def merge(self, v):
        for pid in v.clocks.keys():
            self.clocks[pid] = max([self.get(pid), v.get(pid)])

    def before(self, v):
        if ifilter(lambda p: self.get(p) > v.get(p), v.clocks.keys()):
            return False
        if ifilter(lambda p: p not in self.clocks, v.clocks.keys()):
            return False
        else:
            return True

    def race(self, v):
        return not (self.before(v) or v.before(self))

    def __init__(self, pid, v=None):
        if v:
            self.clocks = dict(v.clocks)
        else:
            self.clocks = dict()
        self.clocks[pid] = 1
        
