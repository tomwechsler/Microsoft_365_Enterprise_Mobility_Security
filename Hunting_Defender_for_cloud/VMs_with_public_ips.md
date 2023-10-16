# Why you should not assign a public IP to a virtual machine in Azure!

Again and again I encounter the situation that a public IP address has been assigned to virtual machines in Azure. Of course, this makes it very easy to manage the machine via this public IP. But the attack surface is thus increased many times over. Let's take a closer look at the information of a virtual machine. I have created a Linux VM with a public IP address to show you the effects.

<img src="/Images/fail2_0.png" alt="Microsoft Azure - Infos about a VM">

After provisioning the virtual machine, I connected to the system and accessed the log files. More precisely, the log files to sshd, the daemon of SSH.

<img src="/Images/fail2_1.png" alt="sshd">

As we can see immediately, an attempt was made to establish a connection using SSH. Always from the same IP address but with different usernames. 

To continue this investigation I installed and configured fail2ban (a very simple configuration). After three unsuccessful login attempts within 10 minutes, the IP address should be blocked for 72 hours.

<img src="/Images/fail2_2.png" alt="fail2ban">

After the configuration I restarted the service and checked the status. As we can see immediately, the IP address we already know from the log files has now been blocked by fail2ban.

<img src="/Images/fail2_3.png" alt="fail2ban status">

I hope this example shows why a virtual machine should never be configured with a public IP address (except perhaps for testing purposes). There are alternatives to manage a virtual machine over the Internet without exposing it.

For example, with the Azure Bastion. In the following link you can find more information:  
https://learn.microsoft.com/en-us/azure/bastion/bastion-overview
