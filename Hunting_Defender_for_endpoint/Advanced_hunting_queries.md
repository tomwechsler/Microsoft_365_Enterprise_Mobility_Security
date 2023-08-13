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

5. Search for specific malicious software

```
let fileName = "cain.exe";
let fileSha1 = "1ce4134548a78ee1df7d9db9f2d8676babab9924";
let fileSha256 = "a0b918730cfa2804ef34e2dae028df3961dda2dd267aa1130fc1a8430be96355";
let selectedTimestamp = datetime(2023-07-27T12:12:55.0000000Z);
search in (EmailAttachmentInfo,DeviceFileEvents,BehaviorEntities,CloudAppEvents)
Timestamp between ((selectedTimestamp - 1h) .. (selectedTimestamp + 1h))
and (FileName =~ fileName
or (ObjectType == 'File' and ObjectName == fileName)
//or SHA1 == fileSha1
//or InitiatingProcessFileName =~ fileName
//or ActivityObjects has fileName
//or InitiatingProcessSHA1 has fileSha1
//or SHA256 == fileSha256
//or InitiatingProcessSHA256 == fileSha256
```
<img src="/Images/Example_5.png" alt="Example 5">

6. The query below obtains the list of phishing and malware detections from the EmailEvents table

```
EmailEvents
| where Timestamp > ago(30d)
//Get email processing events where the messages were identified as either phishing or malware
| where ThreatTypes has "Malware" or ThreatTypes has "Phish"
//Merge email events with identity info to get recipient details
| join (IdentityInfo | distinct AccountUpn, AccountDisplayName, JobTitle,
Department, City, Country) on $left.RecipientEmailAddress == $right.AccountUpn
//Show important message and recipient details
| project Timestamp, NetworkMessageId, Subject, ThreatTypes,
SenderFromAddress, RecipientEmailAddress, AccountDisplayName, JobTitle,
Department, City, Country
```

<img src="/Images/Example_6.png" alt="Example 6">

7. Query for devices that the potentially compromised account has logged onto

```
DeviceInfo
//Query for devices that the potentially compromised account has logged onto
| where LoggedOnUsers contains 'james.west'
| distinct DeviceId
//Crosscheck devices against alert records in AlertEvidence and AlertInfo tables
| join kind=inner AlertEvidence on DeviceId
| project AlertId
//List all alerts on devices that user has logged on to
| join AlertInfo on AlertId
| project AlertId, Timestamp, Title, Severity, Category
```

<img src="/Images/Example_7.png" alt="Example 7">

8. Inspect record

```
let fileName = "c-xsumtc.exe.part";
let fileSha1 = "51c647e2b150e781bd1910cac4061a2cee1daf89";
let fileSha256 = "86e0eac8c5ce70c4b839ef18af5231b5f92e292b81e440193cdbdc7ed108049f";
search in (EmailAttachmentInfo,DeviceFileEvents,BehaviorEntities,CloudAppEvents)
Timestamp between (ago(30d) .. now())
and (FileName =~ fileName
or (ObjectType == 'File' and ObjectName == fileName)
//or SHA1 == fileSha1
//or InitiatingProcessFileName =~ fileName
//or ActivityObjects has fileName
//or InitiatingProcessSHA1 has fileSha1
//or SHA256 == fileSha256
//or InitiatingProcessSHA256 == fileSha256
)
| extend ReportId = coalesce(ReportId_string, tostring(ReportId_long))
```

<img src="/Images/Example_8.png" alt="Example 8">

> Note: The KQL examples are based on incidents from Defender for Endpoint and the Microsoft documentation