from mutator import Mutator
from nodeloc_matcher import NodeLocMatcher
from racepro.session import Event
import scribe

class Bookmark(Mutator):
    def __init__(self, bmarks):
        def valid_bookmark(nl):
            # XXX Not entirely correct. We should check if the bookmark
            # is after the exit syscall
            if nl.node == nl.node.proc.last_anchor:
                return False
            if nl.node == nl.node.proc.first_anchor and nl.before:
                return False
            return True
        bmarks = filter(valid_bookmark, bmarks)

        self.num_procs = len(bmarks)
        self.matcher = NodeLocMatcher(bmarks)

    def start(self, env):
        self.bookmark_id = env.get('next_bookmark_id', 0)
        env['next_bookmark_id'] = self.bookmark_id + 1

    def process_events(self, events):
        for event in events:
            match = self.matcher.match(event)
            if match is not None:
                bmark_event = scribe.EventBookmark()
                if match == 'before':
                    bmark_event.type = scribe.SCRIBE_BOOKMARK_PRE_SYSCALL
                else:
                    bmark_event.type = scribe.SCRIBE_BOOKMARK_POST_SYSCALL
                bmark_event.id = self.bookmark_id
                bmark_event.npr = self.num_procs
                yield Event(bmark_event, event.proc)

            if not (event.is_a(scribe.EventBookmark) and
                    self.bookmark_id == 0):
                yield event
