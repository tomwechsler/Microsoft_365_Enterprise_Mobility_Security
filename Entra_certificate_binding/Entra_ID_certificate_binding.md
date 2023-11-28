# Achieve higher security with certificate bindings!

**Overview of Microsoft Entra certificate-based authentication**  
https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication

**How to configure Microsoft Entra certificate-based authentication**  
https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-certificate-based-authentication

**Microsoft Entra certificate-based authentication technical deep dive**  
https://learn.microsoft.com/en-us/entra/identity/authentication/concept-certificate-based-authentication-technical-deep-dive

**What does it mean "Achieve higher security with certificate bindings"?**  
Microsoft Entra ID, formerly known as Azure Active Directory, is a cloud identity and access management solution that controls application access and protects identities. The term “Achieve higher security with certificate bindings” refers to a feature of Microsoft Entra ID that enhances user authentication security. This feature is part of the certificate-based authentication (CBA) process. Certificate bindings refer to the methods used to bind a certificate to a user’s identity, enhancing the security of the authentication process. There are seven supported methods for certificate bindings. These methods are considered high-affinity if they’re based on identifiers that can’t be reused, such as Subject Key Identifiers or SHA1 Public Key. This way, Microsoft Entra ID provides a secure and efficient way for users to authenticate and access applications..

### Let's examine achieve higher security with certificate bindings.

**Object Identifiers (OID)**  

First we look at the certificate template on the certificate server (sorry some print screens are in German). Here we see the details of the Object Identifiers (OID).

<img src="/Entra_ID_Certificate_binding/Images/OID.png" alt="OID">

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

**The exact info from Fiddler:**  

<img src="/Entra_ID_CAE/Images/cae_9.png" alt="Infos from Fiddler">

---
## *HAPPY EVALUATING!*
---