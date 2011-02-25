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
        try:
            self.clocks[pid] += 1
        except KeyError:
            self.clocks[pid] = 1

    def merge(self, vector):
        for pid in vector.clocks.keys():
            self.clocks[pid] = max([self.get(pid), vector.get(pid)])

    def before(self, vector):
        for pid in vector.clocks.keys():
            if self.get(pid) > vector.get(pid):
                return False
        return self.len() < vector(len)

    def race(self, vector):
        return not (self.before(vector) or vector.before(self))

    def __init__(self, pid, clock=None):
        if clock:
            self.clocks = dict(clock.clocks)
        else:
            self.clocks = dict()
            self.clocks[pid] = 1
        
