## Notes

- Log source: `/var/log/auth.log`
- Detection approach: per-source IP sliding window + threshold + cooldown
- Output: JSON Lines written to `/var/log/custom_ids/ids_alerts.json`
- SIEM forwarding: Splunk monitors the JSONL file and extracts fields via `INDEXED_EXTRACTIONS=json`

### Quick run (manual)
```bash
sudo python3 src/ids_bruteforce.py --mode follow --log /var/log/auth.log --out /var/log/custom_ids/ids_alerts.json --threshold 8 --window 120 --cooldown 300
```

### Systemd checks
```bash
sudo systemctl status custom-log-ids.service --no-pager
sudo journalctl -u custom-log-ids.service -n 100 --no-pager
```

## Useful Splunk Searches

### Count by event type
```spl
index=main sourcetype="custom_ids:json"
| stats count by event_type severity
```

### Bruteforce details
```spl
index=main sourcetype="custom_ids:json" event_type="bruteforce_detected"
| table _time src_ip user_last_seen fail_count_in_window threshold severity raw_sample
| sort - _time
```

### Trend of failures
```spl
index=main sourcetype="custom_ids:json" event_type="ssh_fail_observed"
| timechart span=5m max(fail_count_in_window) as max_fails by src_ip
```
