from mutator import Mutator
from nodeloc_matcher import NodeLocMatcher
from racepro.session import Event
import scribe

relax_map = {
   scribe.SCRIBE_PS_ENABLE_DATA:
       set([scribe.EventData.native_type,
            scribe.EventDataExtra.native_type]),
   scribe.SCRIBE_PS_ENABLE_RESOURCE:
       set([scribe.EventResourceLockExtra.native_type,
            scribe.EventResourceUnlock.native_type,
            scribe.EventResourceLock.native_type,
            scribe.EventResourceLockIntr.native_type])
}

def should_skip_event(event, relaxed_flags):
    for flag in relax_map.keys():
        if relaxed_flags & flag and \
                event.native_type in relax_map[flag]:
            return True

    return False

class Relax(Mutator):
    def __init__(self, relaxations):
        self.matcher = NodeLocMatcher(relaxations)

    def process_events(self, events):
        relaxed_procs = dict()

        def get_inject(event, before):
            flags = self.matcher.match(event, before)
            if flags is None:
                return None

            proc = event.proc
            old_flags = relaxed_procs.get(proc, 0)
            if old_flags == flags:
                return None

            relaxed_procs[proc] = old_flags | flags

            inject_event = scribe.EventInjectAction()
            inject_event.action = scribe.SCRIBE_INJECT_ACTION_PSFLAGS
            inject_event.arg1 = 0
            inject_event.arg2 = flags
            return Event(inject_event, proc)

        for event in events:
            inject_event = get_inject(event, before=True)
            if inject_event is not None:
                yield inject_event

            relaxed_flags = relaxed_procs.get(event.proc, 0)
            skip = relaxed_flags != 0 and \
                  should_skip_event(event, relaxed_flags)
            if not skip:
                yield event

            bmark_event = get_inject(event, before=False)
            if bmark_event is not None:
                yield bmark_event
