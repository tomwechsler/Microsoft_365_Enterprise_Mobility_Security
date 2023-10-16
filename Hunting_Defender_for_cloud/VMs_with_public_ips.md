# Why you should not assign a public IP to a virtual machine in Azure!

Again and again I encounter the situation that a public IP address has been assigned to virtual machines in Azure. Of course, this makes it very easy to manage the machine via this public IP. But the attack surface is thus increased many times over. Let's take a closer look at the information of a virtual machine. I have created a Linux VM with a public IP address to show you the effects.

<img src="/Images/fail2_0.png" alt="Microsoft Azure - Infos about a VM">

After provisioning the virtual machine, I connected to the system and accessed the log files. More precisely, the log files to sshd, the daemon of SSH.

<img src="/Images/fail2_1.png" alt="sshd">

