# J-PWN
Jira Vulnerability Enumeration 

This is a fork of https://github.com/anmolksachan/JIRAya

This vulnerability checks weren't really working correctly and didnt do much in the way of validating or dumping some data if the URL was a 200. I eventually changed enough to just change the name but credit is listed. 🤷‍♂️

### Fixed
* add the ability to specify jira path
* add some fixes to support http/https better
* handle unverified SSL certs

## Install

`pip install -r requirements`

`python3 j-pwn.py --single 1.2.3.4 -p /jira/` (jira path added)

`python3 j-pwn.py --single 5.6.7.8`

### Example Data

Returns JIRA server version if JIRA is identified

```
+ JIRA is running on: https://jira1 

JIRA Server Information:
  Base URL        : https://jira1/jira
  Version         : 7.1.9
  Deployment Type : Server
  Build Number    : 71013
  Build Date      : 2016-06-27T00:00:00.000-0400
  Server Title    : JIRA

+ JIRA is running on: https://jira2

JIRA Server Information:
  Base URL        : https://jira2/jira
  Version         : 8.8.1
  Deployment Type : Server
  Build Number    : 808001
  Build Date      : 2020-04-22T00:00:00.000-0400
  Server Title    : Systems JIRA
```

### List the data if a JIRA server is vulnerable

ex: Unauthenticated Access to JIRA Admin Projects Detected
```
+ Unauthenticated Access to JIRA Admin Projects Detected
  URL: https://jira3/jira/rest/menu/latest/admin

  Admin Projects Details:
    - Key: admin
      Link: https://jira3/jira/secure/project/ViewProjects.jspa
      Label: JIRA administration
      Tooltip: 
      Local: True
      Self: True
      Application Type: jira
```
ex: Unauthenticated Access to JIRA Dashboards
```
+ Unauthenticated Access to JIRA Dashboards Detected
  URL: https://jira4/jira/rest/api/2/dashboard?maxResults=100
  Start At: 0
  Max Results: 100
  Total Dashboards: 1

  Dashboard Details:
    - ID: 10000
      Name: System Dashboard
      API URL: https://jira4/jira/rest/api/2/dashboard/10000
      View URL: https://jira4/jira/secure/Dashboard.jspa?selectPageId=10000
```
ex: Unauthenticated Access to JIRA Project Categories
```
+ Unauthenticated Access to JIRA Project Categories Detected
++ Manually check these for Unauthenticated Access ++
  URL: https://jira5/jira/rest/api/2/projectCategory?maxResults=1000

  Project Categories Details:
    - ID: 10003
      Name: Delivered
      Description: Project Delivered 
      API URL: https://jira5/jira/rest/api/2/projectCategory/10003
    - ID: 10400
      Name: Development
      Description: Development
      API URL: https://jira5/jira/rest/api/2/projectCategory/10400
    - ID: 10201
      Name: Internal
      Description: 
      API URL: https://jira5/jira/rest/api/2/projectCategory/10201
```

ex: CVE-2019-3403
```
+ CVE-2019-3403 Detected
  URL: https://jira3/jira/rest/api/2/user/picker?query=admin
  Total Users Found: 0
  Header: Showing 0 of 0 matching users
  User Details: No users listed.
```
ex: CVE-2019-8449
```
+ CVE-2019-8449 Detected
  URL: https://jira3/jira/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
  Total Users Found: 0
  User Header: Showing 0 of 0 matching users
  User Details: No users listed.
  Total Groups Found: 0
  Group Header: Showing 0 of 0 matching groups
  Group Details: No groups listed.
```

ex: CVE-2019-8442
```
- Checking URL: https://jira3/jira/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
- HTTP Status Code: 200
+ CVE-2019-8442 Detected: Information Disclosure vulnerability found!
  URL: https://jira3/jira/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml

- Checking URL: https://jira3/jira/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml
- HTTP Status Code: 200
+ CVE-2019-8442 Detected: Information Disclosure vulnerability found!
  URL: https://jira3/jira/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/jira-webapp-dist/pom.xml
```

ex CVE-2019-11581

NOT VULN
```
- No CVE-2019-11581 vulnerability detected on: https://jira6/secure/ContactAdministrators!default.jspa
	 **The contact form is not configured and most likely NOT vulnerable.**
```
<img alt="image" src="https://github.com/carnal0wnage/JIRAya/blob/main/img/CVE-2019-11581-notvuln.png">


VULN
```
+ CVE-2019-11581 Detected - The contact form is configured and potential vulnerable [MANUAL REVIEW REQUIRED]
  URL: https://jira7/jira/secure/ContactAdministrators!default.jspa
  Note: Exploitation requires manual steps.
  Note: For this issue to be exploitable at least one of the following conditions must be met:
  1. An SMTP server has been configured in Jira and the Contact Administrators Form is enabled
  2. or an SMTP server has been configured in Jira and an attacker has "JIRA Administrators" access.
  Note:Refer to: https://jira.atlassian.com/browse/JRASERVER-69532 && https://hackerone.com/reports/706841
```
<img alt="image" src="https://github.com/carnal0wnage/JIRAya/blob/main/img/CVE-2019-11581-vuln.png">
