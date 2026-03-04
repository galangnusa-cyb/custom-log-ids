# Custom Log-Based IDS: SSH Brute-Force Detector (Python → Splunk)

A lightweight host-based intrusion detection script that monitors Linux authentication logs (`/var/log/auth.log`) to detect SSH brute-force behavior using a sliding time window and threshold. The script outputs structured JSONL events and forwards them to Splunk via file monitoring.

## What it detects
- SSH failed login bursts (`Failed password`, `Invalid user`)
- Triggers a high-severity event when failures from a single source IP reach the configured threshold within the time window.

## Architecture
1. `ids_bruteforce.py` tails `/var/log/auth.log`
2. Emits JSON Lines to `/var/log/custom_ids/ids_alerts.json`
3. Splunk monitors the JSON file (`sourcetype=custom_ids:json`) and extracts fields automatically

## Output events
- `ssh_fail_observed` (severity: info)
- `bruteforce_detected` (severity: high)

Key fields:
- `time`, `event_type`, `src_ip`, `user`, `fail_count_in_window`, `window_seconds`, `threshold`, `raw_sample`

## Run locally (manual)
```bash
sudo mkdir -p /var/log/custom_ids
sudo python3 src/ids_bruteforce.py \
  --mode follow \
  --log /var/log/auth.log \
  --out /var/log/custom_ids/ids_alerts.json \
  --threshold 8 \
  --window 120 \
  --cooldown 300
```

## View output
```bash
sudo tail -f /var/log/custom_ids/ids_alerts.json
```

# Splunk Ingestion (File Monitor)

## Deploy configs
- configs/splunk_inputs.conf
- configs/splunk_props.conf

## Example deployment
```bash
sudo cp configs/splunk_inputs.conf /opt/splunk/etc/system/local/inputs.conf
sudo cp configs/splunk_props.conf  /opt/splunk/etc/system/local/props.conf
sudo /opt/splunk/bin/splunk restart
```

## Validate in Splunk
```spl
index=main sourcetype="custom_ids:json"
| stats count by event_type severity
```

## Run as a systemd service (optional btw)
Service file: configs/custom-log-ids.service
```bash
sudo cp configs/custom-log-ids.service /etc/systemd/system/custom-log-ids.service
sudo systemctl daemon-reload
sudo systemctl enable --now custom-log-ids.service
sudo systemctl status custom-log-ids.service --no-pager
```
