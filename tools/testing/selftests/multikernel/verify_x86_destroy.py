#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Verify persistent allocation reclamation after a real sender's last put."""
import re


def verify_records(held, final):
    try:
        for key in ('cookie', 'instance', 'image', 'ring', 'manifest', 'pool'):
            if (not isinstance(held.get(key), str) or not re.fullmatch(r'[0-9a-f]{1,16}', held[key])
                    or int(held[key], 16) == 0 or final.get(key) != held[key]):
                raise ValueError('destruction correlation/allocation identity mismatch')
        if len({held[k] for k in ('instance', 'image', 'pool')}) != 3 or held['ring'] == held['manifest']:
            raise ValueError('allocation identities alias')
        for state, done in ((held, False), (final, True)):
            if (state.get('released') is not done or state.get('sent') is not done
                    or state.get('failed') is not False or state.get('retired') is not True
                    or state.get('probed') is not True or type(state.get('send_result')) is not int
                    or state['send_result'] != 0 or type(state.get('probe_result')) is not int
                    or state['probe_result'] != -22):
                raise ValueError('unproven reference hold, pool retirement or lookup removal')
        events = final['events']
        if len(events) != 11 or held['events'] != events[:5]:
            raise ValueError('missing or inconsistent destruction events')
        for index, event in enumerate(events, 1):
            expected_cpus = {0} if index in (1, 7) else {2} if index == 6 else {1} if index < 6 else {0, 1, 2}
            if (any(type(event.get(k)) is not int for k in ('seq', 'point', 'cpu'))
                    or event['seq'] != index or event['point'] != index
                    or event['cpu'] not in expected_cpus or event.get('hardirq') is not False
                    or event.get('irqs_off') is not (index == 2)):
                raise ValueError('early free, missing grace period or invalid release context')
    except (KeyError, ValueError, TypeError) as error:
        return [str(error)]
    return []
