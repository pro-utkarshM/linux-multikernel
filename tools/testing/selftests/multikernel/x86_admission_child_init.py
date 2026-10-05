#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
"""Disposable child: real overlays and bounded process-checkpoint control."""
import json
from pathlib import Path
import sys
import threading
import time

sys.path.insert(0, '/usr/lib/python3/dist-packages')
from x86_host_init import marker
from x86_nested_child_init import main, snapshot, apply_pool

GATE = Path('/sys/kernel/debug/mk-native-concurrency-test')


class Admission:
    def __init__(self):
        self.floor = 0
        self.held = None
        self.thread = None
        self.result = None

    def events(self):
        state = json.loads((GATE / 'events').read_text())
        if state['overflow'] or any(e['point'] == 11 for e in state['events']):
            raise RuntimeError('native checkpoint overflow/timeout')
        return state

    def wait(self, predicate):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            state = self.events()
            result = predicate(state)
            if result:
                return result
            time.sleep(0.02)
        raise RuntimeError('checkpoint observation deadline expired')

    def handle(self, nonce, command):
        from kerf.models import PoolMemoryRegion
        from kerf.pool_diff import PoolDiff
        op, mode = command['op'], command.get('mode')
        if op == 'arm':
            state = self.events()
            self.floor = max((e['seq'] for e in state['events']), default=0)
            self.held = None
            (GATE / 'gate_arm').write_text(f"{command['point']} {command['cpu']} 30")
        elif op == 'controller':
            if self.thread and self.thread.is_alive():
                raise RuntimeError('controller already running')
            self.result = None
            def controller():
                try:
                    self.result = apply_pool(PoolDiff(memory_to_pool=[(-1, 16 * 1024 * 1024)]))
                except Exception as error:
                    self.result = error
            self.thread = threading.Thread(target=controller, daemon=True)
            self.thread.start()
        elif op == 'held':
            def held(state):
                events = [e for e in state['events'] if e['seq'] > self.floor
                          and e['point'] == 9 and e['result'] == command['point']]
                return events[0] if state['active'] and len(events) == 1 else None
            self.held = self.wait(held)
            marker('ADMISSION_HELD', nonce=nonce, mode=mode, event=self.held,
                   point=command['point'], active=True)
            return
        elif op == 'waiting':
            def waiting(state):
                events = [e for e in state['events'] if e['seq'] > self.held['seq'] and e['point'] == 8]
                if events and state['active']:
                    request = events[0]['request']
                    if any(e['point'] == 1 and e['request'] == request for e in state['events']):
                        raise RuntimeError('controller entered while worker held lock')
                    return events[0]
            event = self.wait(waiting)
            marker('ADMISSION_CONTROLLER_WAITING', nonce=nonce, mode=mode, event=event, active=True)
            return
        elif op == 'release':
            (GATE / 'gate_release').write_bytes(b'1')
            self.wait(lambda state: not state['active'])
        elif op == 'finish':
            self.thread.join(8)
            if self.thread.is_alive() or not isinstance(self.result, dict):
                raise RuntimeError(f'controller did not complete: {self.result!r}')
            if self.result['status'] != 'applied':
                raise RuntimeError('controller overlay failed')
            marker('ADMISSION_CONTROLLER_DONE', nonce=nonce, mode=mode, **self.result)
            return
        elif op == 'retire':
            state = snapshot()
            if state['pool_cpus'] or len(state['chunks']) != 1:
                raise RuntimeError('unexpected local pool ownership before retirement')
            result = apply_pool(PoolDiff(memory_to_host=[PoolMemoryRegion(base=b, size=s)
                                                       for b, s in state['chunks']]))
            state = snapshot()
            if result['status'] != 'applied' or state['chunks'] or state['slot'] != '0' or state['park'] != '0':
                raise RuntimeError('local park retirement failed')
            marker('ADMISSION_RETIRED', nonce=nonce, mode=mode, **result, **state)
            return
        elif op == 'snapshot':
            marker('PROCESS_REPLY', nonce=nonce, op=op, state=snapshot())
            return
        elif op == 'drain':
            def draining(state):
                closed = [e for e in state['events'] if e['point'] == 6 and e['seq'] > self.held['seq']]
                if any(e['point'] == 7 for e in state['events']):
                    raise RuntimeError('quiescence completed before accepted work retired')
                return closed[0] if state['active'] and len(closed) == 1 else None
            closed = self.wait(draining)
            marker('ADMISSION_DRAIN_WAITING', nonce=nonce, closed=closed, held=self.held, active=True)
            return
        else:
            raise RuntimeError('unknown process test command')
        marker('PROCESS_REPLY', nonce=nonce, op=op)


if __name__ == '__main__':
    main(Admission().handle, profile='admission')
