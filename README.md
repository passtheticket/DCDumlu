# DCDumlupinar
DCDumlupınar aims to conduct enumeration and persistence on the Active Directory.

![GitHub Logo](images/TCGDumlu.jpg)

## Installation & Start up
```
pip3 install -r requirements.txt
python3 DCDumlu.py
```
Then provide `IP address of DC`, `Domain name`, `Username`, `Password or NT hash` for LDAP connection.  
:warning: **Please note that `Username` must be like `sAMAccountName` value format and hash format must be like `LM:NT` or `NT:NT`.**  
:warning: **On first use, DCDumlu.py may need to be run two or three times for ldap authentication to be successful.** However, these attempts never lock the user if the credential is correct.

![GitHub Logo](images/mavna.PNG)

## Usage
Commands | Descriptions
------------ | -------------
getDomainInfo | Get domain SID, name and MAQ
getPasswordPolicy | Get password policy
getTrustInfo | Get trust relationship information
getHosts | Dump hosts information
getUsers | Dump users information
getGroups | Dump groups information
hostDescriptions | Dump description of hosts information
userDescriptions | Dump description of users information
getGroupMembers | Dump members of specified group
searchUser | Search specific user
searchHost | Search specific host
unconstrainedComputer | Enumerate unconstrained computer account
constrainedComputer | Enumerate constrained computer account
constrainedUser | Enumerate constrained user account
unconstrainedUser | Enumerate unconstrained user account
addUser | Add a user
addUserToGroup | Add a user to group
delUser | Delete a user
getSpns | Getting all user SPNs
setSpn | Set a servicePrincipalName attribute value
unSetSpn | Unset a servicePrincipalName attribute value
addUnconstrained | Modify an object for delegation to any service with Kerberos Auth
addConstrained | Modify an object for delegation to specific service
addAsRepRoasting | Set user option as do not require Kerberos preauthentication for As-Rep Roasting attack
delAsRepRoasting | Set user option as Kerberos preauthentication is required
resetObject | Change userAccountControl attribute of object to reset modifications that are related Kerberos delegation attacks
uacTable | Show values for userAccountControl attribute if you need for resetObject operation
checkConnection | Get connection details
help | Print usage
? | Print usage
exit | Exit

## Details
[DCDumlupınar](https://docs.unsafe-inline.com/inline/dcdumlupinar)
