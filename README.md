[comment]: # "Auto-generated SOAR connector documentation"
# Attivo

Publisher: Attivo  
Connector Version: 1\.0\.0  
Product Vendor: Attivo  
Product Name: BOTsink  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.0\.1068  

Interact with Attivo BOTsink

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a BOTsink asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**botsink** |  required  | string | Name or IP of the Attivo BOTsink
**botsink\_user** |  required  | string | Name of the BOTsink API user
**botsink\_password** |  required  | password | Password for the API user
**verify\_ssl** |  required  | boolean | Verify BOTsink SSL certificate
**ingest\_severity** |  required  | string | Minimum alert severity for ingestion
**first\_fetch** |  required  | numeric | Days to go back for first alert ingest

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[on poll](#action-on-poll) - Ingest alerts from the Attivo BOTsink  
[get events](#action-get-events) - Pull Attivo events based on source IP and timeframe  
[check user](#action-check-user) - Verify whether a user is Deceptive  
[check host](#action-check-host) - Verify whether a host is Deceptive  
[list hosts](#action-list-hosts) - List all deceptive hosts \(network decoys\) on the Attivo BOTsink  
[list users](#action-list-users) - List all deceptive users on the Attivo BOTsink  
[list playbooks](#action-list-playbooks) - List all configured playbooks on the Attivo BOTsink  
[run playbook](#action-run-playbook) - Run a preconfigured Playbook on the Attivo BOTsink  
[deploy decoy](#action-deploy-decoy) - Bring up a network decoy system  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'on poll'
Ingest alerts from the Attivo BOTsink

Type: **ingest**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**severity** |  optional  | Minimum severity of events to retrieve | string | 
**first\_fetch** |  optional  | How many days back to fetch alerts on the first run\. \('0' means don't fetch any historic alerts\) | numeric | 

#### Action Output
No Output  

## action: 'get events'
Pull Attivo events based on source IP and timeframe

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**attacker\_ip** |  required  | The source IP to search for in Attivo alerts | string |  `ip` 
**hours\_back** |  required  | The number of hours ago to start the search | numeric | 
**severity** |  required  | Severity of alerts generated in Attivo | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.attack\_name | string | 
action\_result\.data\.\*\.target\_ip | string |  `ip` 
action\_result\.data\.\*\.severity | string | 
action\_result\.data\.\*\.target\_os | string | 
action\_result\.data\.\*\.timestamp | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.parameter\.attacker\_ip | string |  `ip` 
action\_result\.parameter\.hours\_back | string | 
action\_result\.parameter\.severity | string |   

## action: 'check user'
Verify whether a user is Deceptive

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**user** |  optional  | The user name to verify with Attivo | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.user | string | 
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.is\_deceptive | string | 
action\_result\.data\.\*\.user\_group | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'check host'
Verify whether a host is Deceptive

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**host** |  optional  | The host name or IP address to verify with Attivo | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.host | string | 
action\_result\.data\.\*\.host | string | 
action\_result\.data\.\*\.is\_deceptive | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.vlan | numeric | 
action\_result\.data\.\*\.host\_name | string | 
action\_result\.data\.\*\.mac | string | 
action\_result\.data\.\*\.dhcp | string | 
action\_result\.data\.\*\.td\_name | string | 
action\_result\.data\.\*\.td\_type | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'list hosts'
List all deceptive hosts \(network decoys\) on the Attivo BOTsink

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.host | string | 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.vlan | numeric | 
action\_result\.data\.\*\.mac | string | 
action\_result\.data\.\*\.dhcp | string | 
action\_result\.data\.\*\.td\_name | string | 
action\_result\.data\.\*\.td\_type | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string |   

## action: 'list users'
List all deceptive users on the Attivo BOTsink

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.user | string | 
action\_result\.data\.\*\.groups | string | 
action\_result\.status | string | 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'list playbooks'
List all configured playbooks on the Attivo BOTsink

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.investigate | string | 
action\_result\.data\.\*\.analyze | string | 
action\_result\.data\.\*\.manage | string | 
action\_result\.data\.\*\.isolate | string | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string |   

## action: 'run playbook'
Run a preconfigured Playbook on the Attivo BOTsink

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**playbook\_name** |  required  | The name of the preconfigured Playbook on the Attivo BOTsink | string | 
**attacker\_ip** |  optional  | The attacker IP address to feed to the Playbook | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.playbook\_name | string | 
action\_result\.parameter\.attacker\_ip | string |  `ip` 
action\_result\.status | string | 
action\_result\.data | string | 
action\_result\.summary | string | 
action\_result\.message | string |   

## action: 'deploy decoy'
Bring up a network decoy system

Type: **correct**  
Read only: **False**

Bring up decoy systems on the Attivo BOTsink appliance

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vulnerable\_endpoint** |  required  | This is the description of the target\_network parameter | string |  `ip` 
**decoy\_number** |  optional  | The number of decoy IP addresses to acquire | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.vulnerable\_endpoint | string |  `ip` 
action\_result\.parameter\.decoy\_number | numeric | 
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.summary | string | 
action\_result\.data | string | 