# Red Team


## Engagement

### Scope and Objectives

- Clearly define client objectives and goals
- Define the type of the engagement
	- General : internal & network pentest
	- Focused adversary emulation
		- In this case, decide a team
- Define a scope
	- Define what you can not do
		- Example : no DDoS or DoS
	- Define a target / IP range
		- Example : 10.0.0.8/20

Example :
```
Objectives:

    Identify system misconfigurations and network weaknesses.
        Focus on exterior systems.
    Determine the effectiveness of endpoint detection and response systems.
    Evaluate overall security posture and response.
        SIEM and detection measures.
        Remediation.
        Segmentation of DMZ and internal servers.
    Use of white cards is permitted depending on downtime and length.
    Evaluate the impact of data exposure and exfiltration.

Scope:

    System downtime is not permitted under any circumstances.
        Any form of DDoS or DoS is prohibited.
        Use of any harmful malware is prohibited; this includes ransomware and other variations.
    Exfiltration of PII is prohibited. Use arbitrary exfiltration data.
    Attacks against systems within 10.0.4.0/22 are permitted.
    Attacks against systems within 10.0.12.0/22 are prohibited.
    Bean Enterprises will closely monitor interactions with the DMZ and critical/production systems.
        Any interaction with "*.bethechange.xyz" is prohibited.
        All interaction with "*.globalenterprises.thm" is permitted.
```

### Rules of Engagements

Document that is legally binding outline of the client objectives and scope with further details of engagement expectations between both parties. 
- Acts like a contract between the two parties
- RoE are criticals since it is legally binding contracts


|Section Name	|Section Details|
|:-----|:------|
Executive Summary	| Overarching summary of all contents and authorization within RoE document
Purpose	| Defines why the RoE document is used
References	| Any references used throughout the RoE document (HIPAA, ISO, etc.)
Scope	| Statement of the agreement to restrictions and guidelines
Definitions	| Definitions of technical terms used throughout the RoE document
Rules of Engagement and Support Agreement	| Defines obligations of both parties and general technical expectations of engagement conduct
Provisions	| Define exceptions and additional information from the Rules of Engagement
Requirements, Restrictions, and Authority 	| Define specific expectations of the red team cell
Ground Rules	| Define limitations of the red team cell's interactions
Resolution of Issues/Points of Contact	| Contains all essential personnel involved in an engagement
Authorization	| Statement of authorization for the engagement
Approval 	| Signatures from both parties approving all subsections of the preceding document
Appendix	| Any further information from preceding subsections

### Planning

Each team will have it's methodology but here are four common type of plannig

|Type of Plan	| Explanation of Plan	|Plan Contents|
|:----|:------|:--------|
|Engagement Plan	| An overarching description of technical requirements of the red team. | CONOPS (Concept of Operations, Resource and Personnel Requirements, Timelines |
|Operations Plan	| An expansion of the Engagement Plan. Goes further into specifics of each detail.| Operators, Known Information, Responsibilities, etc.
|Mission Plan	| The exact commands to run and execution time of the engagement.| Commands to run, Time Objectives, Responsible Operator, etc.
|Remediation Plan| Defines how the engagement will proceed after the campaign is finished.| Report, Remediation consultation, etc.

https://redteam.guide/docs/checklists/red-team-checklist/


***CONOPS (CONcept of OPerationS)***  
It details a high-level overview of the proceedings of an engagement (Semi-Technical). Written as a summary.

***Components that should be included in a CONOPS***  
- Client Name
- Service Provider
- Timeframe
- General Objectives/Phases
- Other Training Objectives (Exfiltration)
- High-Level Tools/Techniques planned to be used
- Threat group to emulate (if any)

***Resource plan***  
The resource plan is the second document of the engagement plan, detailing a brief overview of dates, knowledge required (optional), resource requirements.  
Example :
```
Header
    Personnel writing
    Dates
    Customer
Engagement Dates
    Reconnaissance Dates
    Initial Compromise Dates
    Post-Exploitation and Persistence Dates
    Misc. Dates
Knowledge Required (optional)
    Reconnaissance
    Initial Compromise
    Post-Exploitation
Resource Requirements
    Personnel
    Hardware
    Cloud
    Misc.
```