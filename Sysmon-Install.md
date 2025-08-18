# Sysmon Install (Windows)
1. Download Sysmon from Microsoft Sysinternals.
2. Use SwiftOnSecurity config:
   ```
   sysmon64.exe -i sysmonconfig.xml
   ```
3. Forward logs to Splunk via Universal Forwarder.
