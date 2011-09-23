class NodeLocMatcher:
    def __init__(self, matchers):
        self.before = dict((k.node,v) for (k,v) in matchers.items() if k.before)
        self.after  = dict((k.node,v) for (k,v) in matchers.items() if k.after)

    def match(self, event, before):
        if before:
            return self.before.get(event)
        else:
            return self.after.get(event)

