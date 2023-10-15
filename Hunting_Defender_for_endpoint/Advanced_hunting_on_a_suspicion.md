# Advanced hunting on suspicion with Kusto Query Language in Microsoft Defender for Endpoint!!

You can find advanced hunting in the Microsoft 365 Defender Admin Center. - [Microsoft 365 Defender Admin Center](https://security.microsoft.com/v2/advanced-hunting)

<img src="/Images/M365.png" alt="Microsoft 365 Defender Admin Center">

**Log files are (mostly) not examined just like that, but when there is a suspicion or an event has occurred.**  

## KQL Examples

1. Obtain user accounts from email addresses

```
EmailEvents
| where Timestamp > ago(7d)
| project RecipientEmailAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
```

<img src="/Images/Hunt_1.png" alt="Example 1">

2. Obtains the list of phishing and malware detections

```
EmailEvents
| where Timestamp > ago(7d)
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

3. Get device information

```
DeviceInfo
//Query for devices that the potentially compromised account has logged onto
| where LoggedOnUsers contains '<account-name>'
| distinct DeviceId
//Crosscheck devices against alert records in AlertEvidence and AlertInfo tables
| join kind=inner AlertEvidence on DeviceId
| project AlertId
//List all alerts on devices that user has logged on to
| join AlertInfo on AlertId
| project AlertId, Timestamp, Title, Severity, Category
```

4. Get file event information

```
DeviceInfo
| where Timestamp > ago(1d)
| where ClientVersion startswith "20.1"
| summarize by DeviceId
| join kind=inner (
    DeviceFileEvents
    | where Timestamp > ago(1d)
) on DeviceId
| take 10
```

5. Example query for macOS devices

```
DeviceInfo
| where Timestamp > ago(1d)
| where OSPlatform == "macOS" and  OSVersion !contains "10.15" and OSVersion !contains "11."
| summarize by DeviceId
| join kind=inner (
    DeviceInfo
    | where Timestamp > ago(1d)
) on DeviceId
| take 10
```

6. Get device status info

```
DeviceInfo
| where Timestamp > ago(1d)
| where OnboardingStatus != "Onboarded"
| summarize by DeviceId
| join kind=inner (
    DeviceInfo
    | where Timestamp > ago(1d)
) on DeviceId
| take 10
```

<img src="/Images/Hunt_2.png" alt="Example 6">

7. List logon activities of users that received emails that were not zapped successfully

```
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
//List malicious emails that were not zapped successfully
| where ActionType has "ZAP" and ActionResult == "Error"
| project ZapTime = Timestamp, ActionType, NetworkMessageId , RecipientEmailAddress
//Get logon activity of recipients using RecipientEmailAddress and AccountUpn
| join kind=inner IdentityLogonEvents on $left.RecipientEmailAddress == $right.AccountUpn
| where Timestamp between ((ZapTime-24h) .. (ZapTime+24h))
//Show only pertinent info, such as account name, the app or service, protocol, the target device, and type of logon
| project ZapTime, ActionType, NetworkMessageId , RecipientEmailAddress, AccountUpn,
LogonTime = Timestamp, AccountDisplayName, Application, Protocol, DeviceName, LogonType
```

8. Get logon attempts by domain accounts targeted by credential theft

```
AlertInfo
| where Timestamp > ago(30d)
//Get all credential access alerts
| where Category == "CredentialAccess"
//Get more info from AlertEvidence table to get the SID of the target accounts
| join AlertEvidence on AlertId
| extend IsJoined=(parse_json(AdditionalFields).Account.IsDomainJoined)
| extend TargetAccountSid=tostring(parse_json(AdditionalFields).Account.Sid)
//Filter for domain-joined accounts only
| where IsJoined has "true"
//Merge with IdentityLogonEvents to get all logon attempts by the potentially compromised target accounts
| join kind=inner IdentityLogonEvents on $left.TargetAccountSid == $right.AccountSid
//Show only pertinent info, such as account name, the app or service, protocol, the accessed device, and type of logon
| project AccountDisplayName, TargetAccountSid, Application, Protocol, DeviceName, LogonType
```

9. Check if files from a known malicious sender are on your devices

```
EmailAttachmentInfo
| where SenderFromAddress =~ "MaliciousSender@example.com"
//Get emails with attachments identified by a SHA-256
| where isnotempty(SHA256)
| join (
//Check devices for any activity involving the attachments
DeviceFileEvents
| project FileName, SHA256, DeviceName, DeviceId
) on SHA256
| project Timestamp, FileName , SHA256, DeviceName, DeviceId,  NetworkMessageId, SenderFromAddress, RecipientEmailAddress
```

10. Review logon attempts after receipt of malicious emails

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

11. Review PowerShell activities after receipt of emails from known malicious sender

```
//Define new table for emails from specific sender
let EmailsFromBadSender=EmailEvents
| where SenderFromAddress =~ "MaliciousSender@example.com"
| project TimeEmail = Timestamp, Subject, SenderFromAddress, AccountName = tostring(split(RecipientEmailAddress, "@")[0]);
//Merge emails from sender with process-related events on devices
EmailsFromBadSender
| join (
DeviceProcessEvents
//Look for PowerShell activity
| where FileName =~ "powershell.exe"
//Add line below to check only events initiated by Outlook
//| where InitiatingProcessParentFileName =~ "outlook.exe"
| project TimeProc = Timestamp, AccountName, DeviceName, InitiatingProcessParentFileName, InitiatingProcessFileName, FileName, ProcessCommandLine
) on AccountName
//Check only PowerShell activities within 30 minutes of receipt of an email
| where (TimeProc - TimeEmail) between (0min.. 30min)
| take 10
```

12. Quarantine file

```
let fileName = "cain.exe";
let fileSha1 = "1ce4134548a78ee1df7d9db9f2d8676babab9924";
let fileSha256 = "a0b918730cfa2804ef34e2dae028df3961dda2dd267aa1130fc1a8430be96355";
search in (EmailAttachmentInfo,DeviceFileEvents,BehaviorEntities,CloudAppEvents)
Timestamp between (ago(90d) .. now())
and (FileName =~ fileName
or (ObjectType == 'File' and ObjectName == fileName)
//or SHA1 == fileSha1
//or InitiatingProcessFileName =~ fileName
//or ActivityObjects has fileName
//or InitiatingProcessSHA1 has fileSha1
//or SHA256 == fileSha256
//or InitiatingProcessSHA256 == fileSha256
)
| extend ReportId = coalesce(tostring(column_ifexists("ReportId", "")),column_ifexists("ReportId_string", ""),tostring(column_ifexists("ReportId_long","")))
```

<img src="/Images/Hunt_3.png" alt="Example 12">

> Note: The KQL examples are based on incidents from Defender for Endpoint and the Microsoft documentation
https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-query-emails-devices