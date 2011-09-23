class NodeLocMatcher:
    def __init__(self, matchers):
        if isinstance(matchers, list):
            matchers = dict((m, True) for m in matchers)
        if not isinstance(matchers, dict):
            matchers = {matchers: True}

        self.before = dict((k.node,v) for (k,v) in matchers.items() if k.before)
        self.after  = dict((k.node,v) for (k,v) in matchers.items() if k.after)

    def match(self, event, before):
        if before:
            return self.before.get(event)
        else:
            return self.after.get(event)

