# Microsoft Entra ID Continuous access evaluation and how it works!

**What is Microsoft Entra ID Continuous access evaluation (CAE)?**  
https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation

**How should CAE support us?**  
Microsoft Entra ID continuous access evaluation is a feature that helps to improve the security and resilience of cloud applications. It allows Microsoft Entra ID to issue access tokens that are valid for a longer time, but can be revoked immediately if there is a change in the user account or the tenant policy. This way, applications can enforce the latest security policies without relying on the expiration of the access tokens. For example, if an administrator disables a user account or changes the IP address range for accessing the application, the existing access tokens for that user will be invalidated and the user will have to reauthenticate with Microsoft Entra ID. This reduces the risk of unauthorized access and also reduces the number of token requests, which makes the application more resilient to network issues.

**Build resilience by using Continuous Access Evaluation**  
https://learn.microsoft.com/en-us/entra/architecture/resilience-with-continuous-access-evaluation

**Revoke access in (near) real time with Continuous Access Evaluation**  
Continuous Access Evaluation (CAE) allows Microsoft Entra applications to subscribe to critical events that can then be evaluated and enforced. CAE includes evaluation of the following events:

- User account deleted or disabled
- Password for user changed
- MFA enabled for user
- Administrator explicitly revokes a token
- Elevated user risk detected

### Let's examine CAE on the example of a connection with Microsoft Graph.

**Lets start with the following scenario:**  

In the PowerShell ISE we create a connection with Microsoft Graph and in the background we record it all with the Fiddler tool.

<img src="/Entra_ID_CAE/Images/cae_1.png" alt="Connection to Microsoft Graph">

**In the Fiddler tool we copy the access token:**  

<img src="/Entra_ID_CAE/Images/cae_2.png" alt="Copy access token">

**Now we can decode the access token on the web page https://jwt.ms/:**  

<img src="/Entra_ID_CAE/Images/cae_3.png" alt="Decode access token">

**We can see that the access token is valid for approximately 24 hour:**  

<img src="/Entra_ID_CAE/Images/cae_4.png" alt="Access token valid for 24 hours">

**With the fiddler tool we can see that the microsoft graph is continous access evaluation aware:**  

<img src="/Entra_ID_CAE/Images/cae_5.png" alt="Microsoft Graph is CAE aware">

**Now lets generate an event that will revoke the access token:**

<img src="/Entra_ID_CAE/Images/cae_6.png" alt="Generate event">

**Back in the PowerShell ISE we can see that the access token is no longer valid (Request for re-authentication):**  

<img src="/Entra_ID_CAE/Images/cae_7.png" alt="Access token is no longer valid">

**In the Fiddler tool we can see that the access token is no longer valid:**  

<img src="/Entra_ID_CAE/Images/cae_8.png" alt="Access token is no longer valid">

**The exact info from Fiddler**  

<img src="/Entra_ID_CAE/Images/cae_9.png" alt="Infos from Fiddler">