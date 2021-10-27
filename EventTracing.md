# Event Tracing in Windows

1. At the PowerShell, run the following command:

```
logman start AMSITrace -p Microsoft-Antimalware-Scan-Interface Event1 -o AMSITrace.etl -els
```

2. Execute the malware

Ensure the execution is successful

3. Stop the logman

```
logman stop AMSITrace -els
```

4. Parse the contents into text

```
AMSIScriptContentRetrieval > output.txt
```
