import urllib.request
import urllib.error
import json
import ssl

# === CONFIGURATION ===
MISP_URL = 'https://185.38.28.11/events/restSearch'
MISP_KEY = '0dzYBZs2mFGfqtVZ0fOZlIDsZlNM9GtgtT9LiveK' #update key with real

# === Ignore self-signed SSL certs
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# === Prepare POST request
headers = {
    'Authorization': MISP_KEY,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

data = {
    "published": True,
    "to_ids": True
}

request1 = urllib.request.Request(
    MISP_URL,
    data=json.dumps(data).encode(),
    headers=headers,
    method="POST"
)

# === Perform request
try:
    with urllib.request.urlopen(request1, context=ssl_ctx) as response:
        body = response.read().decode()
        result = json.loads(body)
except urllib.error.HTTPError as e:
    print("HTTP Error:", e.code, e.reason)
    print(e.read().decode())
    exit()
except urllib.error.URLError as e:
    print("Connection Error:", e.reason)
    exit()

# === Extract indicators
indicators = []

for event in result.get('response', []):
    attributes = event.get('Event', {}).get('Attribute', [])
    for attr in attributes:
        if attr.get('to_ids') is True:
            indicators.append({
                'type': attr.get('type'),
                'value': attr.get('value'),
                'event_info': event['Event'].get('info', '')
            })

# === Show results
print(f"Retrieved {len(indicators)} confirmed indicators:\n ")
for ioc in indicators:
        print(f"[{ioc['type']}] {ioc['value']} ← {ioc['event_info']}")

# === Generate Suricata rules
rules = []
sid_base = 3000000

for idx, ioc in enumerate(indicators):
    ioc_type = ioc['type']
    ioc_value = ioc['value']
    info = ioc['event_info']
    sid = sid_base + idx
    msg = f'MISP alert: {info} [{ioc_type}]'

    rule = None
    if ioc_type == 'ip-dst':
        rule = f'alert ip any any -> {ioc_value} any (msg:"{msg}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'ip-src':
        rule = f'alert ip {ioc_value} any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'domain':
        rule = f'alert dns any any -> any any (msg:"{msg}"; content:"{ioc_value}"; nocase; sid:{sid}; rev:1;)'
    elif ioc_type == 'url':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_uri; sid:{sid}; rev:1;)'
    elif ioc_type in ['md5', 'sha1', 'sha256']:
        rule = f'alert http any any -> any any (msg:"{msg}"; filemd5:"{ioc_value}"; sid:{sid}; rev:1;)'

    if rule:
        rules.append(rule)

# === Save to file
rules_file = "rules/misp_suricata.rules"
with open(rules_file, 'w') as f:
    for rule in rules:
        f.write(rule + '\n')

print(f"Saved {len(rules)} Suricata rules to {rules_file}")
