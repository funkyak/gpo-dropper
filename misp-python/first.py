from pymisp import PyMISP, MISPEvent, MISPAttribute
import os
import json

# === CONFIGURATION ===
MISP_URL = 'https://localhost'
MISP_KEY = 'r4j7kDsNugA8QRUmwYx80LnfM2k1juWQIPflP7cP'
VERIFY_SSL = False
EVENT_NAME = 'Suricata IOC Feed'
RULES_FILE = 'misp_suricata.rules'

# === Connect to MISP
misp = PyMISP(MISP_URL, MISP_KEY, VERIFY_SSL, 'json')

# === Step 1: Find or create IOC event
def get_or_create_event(title):
    events = misp.search(controller='events', value=title)
    if events:
        print(f"🔄 Reusing existing event ID {events[0]['Event']['id']}")
        return events[0]['Event']['id']
    else:
        event = MISPEvent()
        event.info = title
        event.distribution = 0
        event.threat_level_id = 2
        event.analysis = 1
        created = misp.add_event(event)
        print(f"✅ Created new event ID {created['Event']['id']}")
        return created['Event']['id']

event_id = get_or_create_event(EVENT_NAME)

# === Step 2: Add sample IOCs to that event
ioc_values = ['45.77.89.34', 'badguy.org', 'http://malicious.example.com', '8e4e5d14bb93ad72fd580df74f6f3a77']

for val in ioc_values:
    attr = MISPAttribute()
    attr.value = val
    attr.to_ids = True
    if val.startswith('http'):
        attr.type = 'url'
    elif '.' in val and not val.startswith('http'):
        attr.type = 'domain' if not val.replace('.', '').isdigit() else 'ip-dst'
    elif len(val) in [32, 40, 64]:  # rudimentary hash length check
        attr.type = {32: 'md5', 40: 'sha1', 64: 'sha256'}[len(val)]
    else:
        continue
    misp.add_attribute(event_id, attr)

# === Step 3: Fetch IOCs from this event
events = misp.search(eventid=event_id, pythonify=True)
indicators = []

for event in events:
    if hasattr(event, 'attributes'):
        for attr in event.attributes:
            if attr.to_ids:
                indicators.append({
                    'type': attr.type,
                    'value': attr.value,
                    'info': event.info,
                    'sid': 3000000 + attr.id
                })

# === Step 4: Convert to Suricata rules
suricata_rules = []

for ioc in indicators:
    rule = None
    msg = f"MISP alert: {ioc['info']} [{ioc['type']}]"
    sid = ioc['sid']
    val = ioc['value']

    if ioc['type'] == 'ip-dst':
        rule = f'alert ip any any -> {val} any (msg:"{msg}"; sid:{sid}; rev:1;)'
    elif ioc['type'] == 'ip-src':
        rule = f'alert ip {val} any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
    elif ioc['type'] == 'domain':
        rule = f'alert dns any any -> any any (msg:"{msg}"; content:"{val}"; nocase; sid:{sid}; rev:1;)'
    elif ioc['type'] == 'url':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{val}"; http_uri; sid:{sid}; rev:1;)'
    elif ioc['type'] in ['md5', 'sha1', 'sha256']:
        rule = f'alert http any any -> any any (msg:"{msg}"; filemd5:"{val}"; sid:{sid}; rev:1;)'

    if rule:
        suricata_rules.append(rule)

# === Step 5: Write rules to file
with open(RULES_FILE, 'w') as f:
    for rule in suricata_rules:
        f.write(rule + '\n')

print(f"\n✅ Done! {len(suricata_rules)} Suricata rules written to {RULES_FILE}")
