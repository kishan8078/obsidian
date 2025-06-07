1. ==**Tech Profiling**==
	1. Finding information about target
		1. WhatRuns
		2. wappalyzer
		3. webanalyze-cmd
2. ==**Finding CVE's and Misconfigs**==
	1. Analyze target:
		1. Known vulnerabilities
		2. Framekwork login pages
		3. Default creds
		4. And more - [what does this even mean?]
	2. Nuclei Scanner
	3. Jaeles Scanner
	4. Retire.js
	5. Sniper
	6. Intrigue Core
	7. GoFingerprint
	8. Vulners
3. ==**Port Scanning**==
	1. Nmap
	2. Naabu
	3. Rustscan
4. ==**Content Discovery/Web Fuzzing**==
	1. Turbo Intruder
	2. GoBuster
	3. WFuzz
	4. FFuf
	5. Dirsearch
	6. Derby
	7. FeroxBuster-[liked by Jason Haddix]
	8. IIS / MSF
		1. httparchive_aspx_asp_cfm_svc_ashx_asmx_...
		2. IIS Shortname Scanner
	9. PHP + CGI
		1. httparchive_cgi_pl_....
		2. httparchive_php...
	10. General API
		1. httparchive_apiroutes...
		2. swagger-wordlist.txt
		3. https:github.com/danielmeissler/SecLists/blob/master/Discovery/Web-Content/api/api-endpoints.txt
	11. Java
		1. httparchive_jsp_jspa_do_action...
	12. Generic
		1. httparchive_directories_im_...
		2. RAFTY
		3. Robots Dissallowed
		4. https://github.com/six2dez/OneListForAll
		5. jhaddix/content_discovery_alt.txt
	13. Others
		1. AEM|Apache|Cherrypy|Coldfusion|Django|Express|Flask|:aravel|Rails|Nginx|Zend
	14. Pay attention to:
		1. Config files for DB connection
		2. Where admin login, routes/endpoints are
	15. Historical Content Discovery
		1. getallurls
		2. wordlistgen
		3. waymore
	16. Recursion
		1. admin/dashboard		                      401
		2. admin/dashboard/member		      401
		3. admin/dashboard/member/staff1	      200
	17. [OPTIONAL] Create custom-dynamic wordlist
		1. Source2URL by Daniel Miessler [danielmiessler/Source2URL]
		2. Scavenger by Dexter [OxDexterOus/Scavenger][burp plugin]
	18. [OPTIONAL] APKLeaks
	19. [OPTIONAL] Follow newsletter
		1. Lets us know 
		2. whenever they add new feature
		3. new beta feature			
		4. new tech integration
		5. new updates
		6. THen Attack on new feature
5. ==**Questions**==
	1. [#1]	How does the app pass data?
	2. [#2]	How/Where does the app  pass about users?
		1. How-{UID,email,username,UUID}
		2. Where-{Cookies,API calls}
	3. [#3]	Does the site have muti-tenancy / user levels?		
		1. {Admin,User,Viewer,Unauthenticates}
	4. [#4]	Does the site have unique threat model?
	5. [#5]	Has there been past security research & vulns?
	6. [#6]	Google How does the app hande:
		1. {XSS,CSRF,Injections}
6. ==**Spidering**==
	1. GUI - Zap, Burp
	2. CMD - Hakrawler, GoSpider
7. **J**==**avascript** **Parsing==**
	1. LinkFinder
	2. XNLinkFinder by Xnl-h4ck3r
	3. Gap - Burp extension [alternate of XnLinkFinder]
	4. Beutifier.io - ObfuscatedJs to readableJs	[Check on Matsuu_ for better tool]
8. ==**Parameter Analysis**==
	1. jaddix/sus_params - [has all of below]
	2. BurpBounty [paid, find any alternate]
	3. HUNT/Burp/conf/issues.json
	4. lutfumertceylan/top25-parameter/tree/master/gf-patterns
	5. 1ndian133t/GF-Patterns
	6. emadshanab/GF-Patterns-Collection
	7. mrofisr/gf=patterns
	8. my/vouchers/v1MySXOKfd5t7-3uOZPNoOd4G-PeSIGp/voucher
9. **==Heat== ==Mapping==**



     