# p1rat3
p1rat3 is A Web-App assisting in the reconnaissance of an internet-facing host systems for an organization's infrastructures for a certain domain.


It is capable of looking for open ports for the specified domain.
Additionally, it lists the Tech Stack used to create the website for that domain and provides the version of the Tech Stack that is useful for identifying known vulnerabilities associated with that specific version.
Furthermore, this web app tests for security vulnerabilities such as Cross-Site Scripting (XSS), Sub-Domain Takeover, and determines whether the tech stack is vulnerable in accordance with known Common Vulnerabilities and Exposures (CVE).
A user-friendly interface will display the complete result of the recon. Not only shows type of vulnerability but also the specification about it.

<br>

## Features:
* The web app only needs the domain. The results are presented in a structured manner.
* Checks 
  * Open ports
  * Tech-Stack
  * Sub-Domain
  * Sub-directories
* Shows Results for:
  * Port-scan
  * Tech-Stack Scan
    * Version
    * Vulerability if found for the version 
  * XSS-vulnerability
    * URLS
    * Paramters
    * Payloads
  * Sub-Domains
    * Also sub-domains which are vulnerable.

<br>   

## Installation

- git clone https://github.com/TitanCrew/p1rat3
- cd p1rat3
- docker build -t p1rat3 .
- docker run -p 6969:6969 --name=p1rat3 p1rat3 

Open http://127.0.0.1:6969 in your browser to access the website.

<br>

## Future Work:
* Multi-threading : To speed things up
* Look out for RCE threats.
*  Look out for injection-based attacks.
