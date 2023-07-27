# Analyze Defender for endpoint logs with Kusto Query Language (KQL)!


## KQL Examples

1. Get device information

```
DeviceInfo
//Query for devices that the potentially compromised account has logged onto
| where LoggedOnUsers contains 'Max.Muster'
| distinct DeviceId
//Crosscheck devices against alert records in AlertEvidence and AlertInfo tables
| join kind=inner AlertEvidence on DeviceId
| project AlertId
//List all alerts on devices that user has logged on to
| join AlertInfo on AlertId
| project AlertId, Timestamp, Title, Severity, Category
```

<img src="/Images/Example_1.png" alt="Example 1">

