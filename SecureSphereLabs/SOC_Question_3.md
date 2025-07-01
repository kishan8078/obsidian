SQLi
XSS
CSRF
SSRF
CORS
IDORS
Broken Authentication

JWT vs OAuth2:
	OAuth1 vs OAuth2:
		OAuth1 was difficult for developers to implement due to the need for custom cyrptographic handling.
		It used complex system of signing request using HMAC-SHA1 signatures to ensure authenticity and integrity.
	
	OAuth:
	OAuth2 is a authorization protocol. Doesn't contain user info(username, 
	email) It defines how tokens are issued, validated, refreshed.
	Handles permissions, scope, access control of a user.
	To get user info, OpenID Connect is used.

	JWT:
	JWT is a Token format.It contains information such as user id 
	(username,email). On every API request server will decode actual user info 
	and then processes rest of the code for that specific user.
	
	Whenever JWT or OAuth2 gets expired, refresh token is sent to server, server 
	then issues new access Token (JWT or OAuth).

	Token could be stolen by:
		XSS , CSRF , MITM
		Extensions if not HttpOnly is applied to tokens

	Attacker could:
		Get all information relative to this user.
		Establish persistence, if refresh token is compramised.
		Imitate actual users browser, OS, geoLocation, etc to prevent detection.
	
	Detected by:
		Sudden change in GEoLocation.
		constant switch between Device fingerPrints such as browser-agent, OS.
		Same token used more than normal.
		Tools: 
			SIEM[splunk, Sentinel, Elastic]
			EDR/XDR
			WAF logs , IAM event logs

	Response:
		Identify the user.
		Revoke tokens: delete OAuth token from DB, blacklist JWT.
		Force logout.
		Notify user, suggest password change, enable MFA.

		In case attacker imitates actual user environment:
			It is difficult to detect but not impossible.
			Check:
				Screen resolution, font.
				Refresh token overused from different IPs, device.
				
As an SOC or security engineer, how would you start on new client (website)?
	Phase 1 : Reconnaissance and Planning
		1. Understand bussines context:
			What does the website do?(e-commerce,download,banking)
			What are important assets (user info,payment)
			Who are threat actors(users,attackers)
		2. Define scope:
			Public, Private APIs.
			Third party integrations.
		3. Integrations:
			SIEM tools (Splunk, QRadar)
				WAF logs, Application logs
	Phase 2 : Baseline Security Audit
		Run OWASP Top Ten : XSS , SQLi , CSRF , SSRF , IDORS , CORS misconfiguration
		Make sure:
			Login is brute-force protected
			Cookie security: httpOnly , secure , SameSite
	Phase 3 : Monitoring and Threat Detection
		SIEM monitoring (auth logs, application logs, api activity) , EDR

Explain SQLi , XSS , CSRF , SSRF , CORS , IDORS , Broken Authentication. how these attacks work (explain in detail, paragraph wise just like any other good book). how attackers might misuse these vulns. how to detect these as an SOC. what are the precautionary measures can be taken? how to detect these attacks? and what to do if each of them are detected?

SQLi:
	is when an attacker injects malicious SQL payloads to form inputs, URL query parameters, headers trying to cause unexpected error on the backend server which then leads to leakage of sensitive information or error messages which are not be seen by users.
	
	Detected by:
		Unexpected SQL errors in logs.
		Sudden spike in DB queries.
		And additionally, IDS/IPS might trigger alert upon detecting common SQLi 
		payloads.


Multiple alerts of attack pops-up, how would you prioratize attacks? what actions you'd take?

SIEM, SNORT, MFA

