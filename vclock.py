class VectorClock:
    """Classic vector clock"""

    def tick(self, pid):
        try:
            self.clocks[pid] += 1
        except KeyError:
            self.clocks[pid] = 1

    def merge(self, vector):
        for pid in vector.clocks.keys():
            self.clocks[pid] = max([self.get(pid), vector.get(pid)])

    def __init__(self, pid, clock=None):
        if clock:
            self.clocks = dict(clock.clocks)
        else:
            self.clocks = dict()
            self.clocks[pid] = 1
        
