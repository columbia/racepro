from racepro.session import Event
import scribe

class NodeLocMatcher:
    def __init__(self, matchers):
        if isinstance(matchers, list):
            matchers = dict((m, None) for m in matchers)
        if not isinstance(matchers, dict):
            matchers = {matchers: None}
        for k in matchers.keys():
            if matchers[k] is None:
                if k.before:
                    matchers[k] = 'before'
                else:
                    matchers[k] = 'after'

        self.before = dict((k.node,v) for (k,v) in matchers.items() if k.before)
        self.after  = dict((k.node,v) for (k,v) in matchers.items() if k.after)

        # When maching on a after syscall, we need to match only after the
        # end syscall.
        self.convert_after_to_end_syscalls()

        #######################################################################
        # XXX Because things don't work well when chaining Mutators with the
        # after matcher (events would be processed in the reverse order), we
        # convert all after matchers in before matchers.
        #######################################################################
        self.convert_after_to_before()

    def convert_after_to_end_syscalls(self):
        def after_end_sys(node):
            if isinstance(node, Event) and node.is_a(scribe.EventSyscallExtra):
                for next_event in node.proc.events.after(node):
                    if next_event.is_a(scribe.EventSyscallEnd):
                        return next_event
            return node

        self.after = dict(map(lambda (k,v): (after_end_sys(k), v), \
                              self.after.items()))

    def convert_after_to_before(self):
        for (node,v) in self.after.items():
            proc = node.proc
            if node == proc.first_anchor:
                next_node = proc.events[0]
            elif node == proc.last_anchor:
                next_node = node
            else:
                try:
                    next_node = node.proc.events.after(node).next()
                except StopIteration:
                    next_node = proc.last_anchor
            if self.before.has_key(next_node):
                raise 'FIXME before/after collapse'
            self.before[next_node] = v

    def match(self, event):
        return self.before.get(event)
