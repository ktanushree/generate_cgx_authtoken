# CloudGenix Generate Auth Tokens
This script can be used to generate a CloudGenix auth token

#### Synopsis
Use this script to generate an auth token for a specific role or a set of roles, with or without an expiration date.

#### Requirements
* Active CloudGenix Account
* Python >= 2.7 or >=3.6
* Python modules:
    * CloudGenix Python SDK >= 5.4.3b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `genauthtoken.py`. 

### Examples of usage:
Generate Auth Token for a single role:
```
./genauthtoken.py -R super 
```
Generate Auth Token for multiple roles:
``` 
./genauthtoken.py -R secadmin,iamadmin  
```
Generate Auth Token with an expiration date:
``` 
./genauthtoken.py -R viewonly -ED 2021-02-02T00:00:00Z  
```

Use the -H hours to specify the time delta in hours for the event query.

Help Text:
```angular2
TanushreeMacBook:generate_authtoken tanushree$ ./genauthtoken.py -h
usage: genauthtoken.py [-h] [--controller CONTROLLER] [--email EMAIL]
                       [--pass PASS] [--roles ROLES]
                       [--expirationdate EXPIRATIONDATE]

CloudGenix: Generate Auth Token.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod:
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Auth Token Specific information:
  Information shared here will be used to create an auth token

  --roles ROLES, -R ROLES
                        Roles. Allowed values: super, viewonly, secadmin,
                        nwadmin, iamadmin. Multiple roles should be comma
                        separated
  --expirationdate EXPIRATIONDATE, -ED EXPIRATIONDATE
                        Expiration Date in format YYYY-MM-DDTHH:MM:SSZ
TanushreeMacBook:generate_authtoken tanushree$ 

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional CloudGenix Documentation at <http://support.cloudgenix.com>
