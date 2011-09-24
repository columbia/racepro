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
    try:
        native_type = event.native_type
    except:
        return False

    for flag in relax_map.keys():
        if relaxed_flags & flag and \
                native_type in relax_map[flag]:
            return True

    return False

class Relax(Mutator):
    def __init__(self, relaxations):
        self.matcher = NodeLocMatcher(relaxations)

    def process_events(self, events):
        relaxed_procs = dict()

        for event in events:
            flags = self.matcher.match(event)
            if flags is not None:
                proc = event.proc
                old_flags = relaxed_procs.get(proc, 0)
                if old_flags != flags:
                    relaxed_procs[proc] = old_flags | flags

                    inject_event = scribe.EventInjectAction()
                    inject_event.action = scribe.SCRIBE_INJECT_ACTION_PSFLAGS
                    inject_event.arg1 = 0
                    inject_event.arg2 = flags
                    yield Event(inject_event, proc)

            relaxed_flags = relaxed_procs.get(event.proc, 0)
            skip = relaxed_flags != 0 and \
                       should_skip_event(event, relaxed_flags)
            if not skip:
                yield event
