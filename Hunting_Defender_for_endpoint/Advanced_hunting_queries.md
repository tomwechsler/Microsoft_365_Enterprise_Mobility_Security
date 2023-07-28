# Analyze Defender for endpoint logs with Kusto Query Language (KQL)!

You can find advanced hunting in the Microsoft 365 Defender Admin Center. - [Microsoft 365 Defender Admin Center](https://security.microsoft.com/v2/advanced-hunting)

<img src="/Images/M365.png" alt="Microsoft 365 Defender Admin Center">

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

2. Review logon attempts after receipt of malicious emails

```
//Define new table for malicious emails
let MaliciousEmails=EmailEvents
//List emails detected as malware, getting only pertinent columns
| where ThreatTypes has "Malware"
| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
MaliciousEmails
| join (
//Merge malicious emails with logon events to find logons by recipients
IdentityLogonEvents
| project LogonTime = Timestamp, AccountName, DeviceName
) on AccountName
//Check only logons within 30 minutes of receipt of an email
| where (LogonTime - TimeEmail) between (0min.. 30min)
| take 10
```

<img src="/Images/Example_2.png" alt="Example 2">

3. AlertInfo table by ServiceSource

```
AlertInfo
| where Timestamp > ago(7d)
| where ServiceSource == "Microsoft Defender for Endpoint"
| join AlertEvidence on AlertId
```

<img src="/Images/Example_3.png" alt="Example 3">

4. Search for a specific file

```
let fileName = "eicar.com";
let fileSha1 = "3395856ce81f2b7382dee72602f798b642f14140";
let fileSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
search in (EmailAttachmentInfo,DeviceFileEvents,BehaviorEntities,CloudAppEvents)
Timestamp between (ago(1d) .. now())
and (FileName =~ fileName
or (ObjectType == 'File' and ObjectName == fileName)
//or SHA1 == fileSha1
//or InitiatingProcessFileName =~ fileName
//or ActivityObjects has fileName
//or InitiatingProcessSHA1 has fileSha1
//or SHA256 == fileSha256
//or InitiatingProcessSHA256 == fileSha256
)
```

<img src="/Images/Example_4.png" alt="Example 4">

> Note: The KQL examples are based on incidents from Defender for Endpoint and the Microsoft documentation