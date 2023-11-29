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

**Object Identifiers (OID):**  

First we look at the certificate template on the certificate server (sorry some print screens are in German). Here we see the details of the Object Identifiers (OID).

<img src="/Entra_certificate_binding/Images/OID.JPG" alt="OID">

**Add a new rule:**  

Configure an additional rule in the Entra ID Admin Center and use the same Object Identifiers (OID) value here as in the certificate template.

<img src="/Entra_certificate_binding/Images/OID_Entra.JPG" alt="Rule">

**Subject Key Identifier (SKID):**  

The certificate was issued on the user's system. We obtain the subject key identifier (SKID) from this certificate. We need this value in the Entra ID Admin Center to assign it to a person. The same person for whom the certificate was issued on the system (in my case it is Tina Fluenza).

<img src="/Entra_certificate_binding/Images/SKI_local_user.JPG" alt="SKID">

**Authorization info:**  

In the Entra ID Admin Center, we now set the value of the Subject Key Identifier (SKID) for the user in the properties.

<img src="/Entra_certificate_binding/Images/SKI_Entra_ID.JPG" alt="Authorization info">

> Note: Please pay attention to the syntax (X509:\<SKI\>).

**Entra ID Sign-In Logs:**  

The "Tina Fluenza" has now registered on the portal https://myapps.microsoft.com and selected the certificate during the application process. This information can be found in the Entra ID Admin Center in the sign-in logs. With the confirmation of MFA by the claim in the token.

<img src="/Entra_certificate_binding/Images/Claim_in_Token.JPG" alt="Sign-In Logs">

---
## *HAPPY BINDING!*
---