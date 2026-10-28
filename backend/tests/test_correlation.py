from copy import deepcopy
from datetime import datetime, timedelta, timezone

from backend.app.store import correlate

BASE = datetime(2026,10,28,8,0,tzinfo=timezone.utc)

def event(number, minutes=0, **changes):
    row = {'id':f'evt-{number}', 'timestamp':(BASE+timedelta(minutes=minutes)).isoformat(),
           'identity':f'user-{number}', 'host':f'host-{number}', 'ip':f'192.0.2.{number}',
           'source':'auth','suspicious':True,'confidence':.9,
           'evidence':[{'feature':'auth_anomaly','category':'credential compromise','explanation':'New device with impossible travel.'}]}
    row.update(changes)
    return row

def test_identity_host_and_ip_connect_across_sources():
    rows = [event(1,identity='shared'),event(2,1,identity='shared',host='bridge',source='email'),
            event(3,2,host='bridge',ip='192.0.2.200',source='network'),event(4,3,ip='192.0.2.200')]
    incidents = correlate(rows)
    assert len(incidents) == 1
    assert set(incidents[0]['event_ids']) == {e['id'] for e in rows}

def test_time_boundary_and_unrelated_events_do_not_merge():
    assert len(correlate([event(1,identity='shared'),event(2,30,identity='shared')])) == 1
    assert len(correlate([event(1,identity='shared'),event(2,31,identity='shared')])) == 2
    assert len(correlate([event(1),event(2,1)])) == 2

def test_benign_context_retained_without_creating_benign_incidents():
    rows = [event(1,identity='shared'),event(2,1,identity='shared',suspicious=False,evidence=[]),
            event(3,2,suspicious=False,evidence=[])]
    original = deepcopy(rows)
    incidents = correlate(list(reversed(rows)))
    assert rows == original
    assert len(incidents) == 1
    assert incidents[0]['event_ids'] == ['evt-1','evt-2']
