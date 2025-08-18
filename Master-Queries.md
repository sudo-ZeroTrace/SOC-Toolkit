# Master Queries Library (SPL)

## Windows Failed Logons
```
index=security sourcetype=wineventlog EventCode=4625
| stats count by src_ip, user
| sort - count
```

## Windows Success Logons
```
index=security sourcetype=wineventlog EventCode=4624
| timechart count by user span=15m
```

## Privilege Escalation (4672)
```
index=security sourcetype=wineventlog EventCode=4672
| stats count by user, host
```

## Account Creation / Changes
```
index=security sourcetype=wineventlog EventCode IN (4720,4722,4723,4724,4725,4738)
| stats count by EventCode, user, target_user, host
```

## Linux SSH Failures
```
index=security sourcetype=linux_secure "Failed password"
| stats count by src_ip, user
```

## Port Scan (Firewall)
```
index=network sourcetype=firewall action=blocked
| bin _time span=1m
| stats dc(dest_port) AS unique_ports by src_ip, _time
| stats max(unique_ports) AS max_ports by src_ip
| where max_ports > 20
```

## DNS Tunneling Suspicion
```
index=dns sourcetype=*dns*
| eval label=len(query)
| stats avg(label) AS avg_len, count BY query, src_ip
| where avg_len > 40 AND count > 50
```

## Malware Beaconing (Regular Intervals)
```
index=network sourcetype=proxy OR sourcetype=firewall
| timechart count by dest_ip span=5m
```

## Sysmon Process Creation
```
index=security sourcetype=sysmon EventID=1
| table _time, host, user, parent_process, process_name, command_line
```

## Suspicious LOLBins (Windows)
```
index=security sourcetype=sysmon EventID=1 process_name IN (powershell.exe, certutil.exe, mshta.exe, wmic.exe, rundll32.exe, regsvr32.exe)
| stats count by host, user, process_name, parent_process
```

