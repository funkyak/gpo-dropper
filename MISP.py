import urllib.request
import urllib.error
import json
import ssl
import os
from dotenv import load_dotenv

# CONFIGURATION
load_dotenv()
MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY")


# Ignore self-signed SSL certs
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

# Prepare POST request
headers = {
    'Authorization': MISP_KEY,
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

data = {
    "published": True
    #"to_ids": True
}

request1 = urllib.request.Request(
    MISP_URL,
    data=json.dumps(data).encode(),
    headers=headers,
    method="POST"
)

# Perform request
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

# Extract indicators
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

# Show results
print(f"Retrieved {len(indicators)} confirmed indicators:\n ")
for ioc in indicators:
        print(f"[{ioc['type']}] {ioc['value']} ← {ioc['event_info']}")

# Generate Suricata rules
rules = []
sid_base = 3000000
# Create rules based on IOC types
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
    elif ioc_type == 'email-src':
        rule = f'alert smtp any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'email-dst':
        rule = f'alert smtp any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'filename':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_uri; sid:{sid}; rev:1;)'
    elif ioc_type == 'asn':
        rule = f'alert ip any any -> any any (msg:"{msg}"; asn:{ioc_value}; sid:{sid}; rev:1;)'
    elif ioc_type == 'cidr':
        rule = f'alert ip any any -> any any (msg:"{msg}"; iprange:{ioc_value}; sid:{sid}; rev:1;)'
    elif ioc_type == 'url-path':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_uri; sid:{sid}; rev:1;)'
    elif ioc_type == 'user-agent':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_header; sid:{sid}; rev:1;)'
    elif ioc_type == 'http-method':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_method; sid:{sid}; rev:1;)'
    elif ioc_type == 'http-cookie':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_cookie; sid:{sid}; rev:1;)'
    elif ioc_type == 'http-header':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; http_header; sid:{sid}; rev:1;)'
    elif ioc_type == 'netmask':
        rule = f'alert ip any any -> any any (msg:"{msg}"; netmask:{ioc_value}; sid:{sid}; rev:1;)'
    elif ioc_type == 'port':
        rule = f'alert ip any any -> any {ioc_value} (msg:"{msg}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'email-subject':
        rule = f'alert smtp any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'email-body':
        rule = f'alert smtp any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'attachment':
        rule = f'alert http any any -> any any (msg:"{msg}"; content:"{ioc_value}"; file_data; sid:{sid}; rev:1;)'
    elif ioc_type == 'regkey':
        rule = f'alert windows any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'regvalue':
        rule = f'alert windows any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'mutex':
        rule = f'alert windows any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'process-name':
        rule = f'alert windows any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    elif ioc_type == 'text':
        rule = f'alert ip any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'
    else :
        rule = f'alert ip any any -> any any (msg:"{msg}"; content:"{ioc_value}"; sid:{sid}; rev:1;)'

#  Add more IOC types as needed 

    if rule:
        rules.append(rule)

# Save to file
rules_file = "rules/misp_suricata.rules"
with open(rules_file, 'w') as f:
    for rule in rules:
        f.write(rule + '\n')

print(f"Saved {len(rules)} Suricata rules to {rules_file}")
