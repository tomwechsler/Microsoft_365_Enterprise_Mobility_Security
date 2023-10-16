# Why you should not assign a public IP to a virtual machine in Azure!

Again and again I encounter the situation that a public IP address has been assigned to virtual machines in Azure. Of course, this makes it very easy to manage the machine via this public IP. But the attack surface is thus increased many times over.

<img src="/Images/fail0_1.png" alt="Microsoft Azure - Infos about a VM">

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