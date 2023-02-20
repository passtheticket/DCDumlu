#!/usr/bin/python3
# -*- coding: utf-8 -*-
import getpass
import sys

import socket
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE, ALL_ATTRIBUTES
from ldap3.extend.microsoft.addMembersToGroups import ad_add_members_to_groups as addUserToGroups
from prettytable import PrettyTable
from colorama import Style
from impacket.ldap import ldaptypes

import convertsid
import banner
import uactable
import usage


class dcDumlu():

    def __init__(self, server, domainName, username, password, operation, searchBaseName):
        self.server = server
        self.domainName = domainName
        self.username = username
        self.password = password
        self.operation = operation
        self.searchBaseName = searchBaseName

    def main(self):

        # define the server and the connection
        s = Server(self.server, get_info=ALL)
        c = Connection(s, user=self.domainName + "\\" + self.username, password=self.password, authentication=NTLM)
        # Hash format | LM:NT hash or NT:NT hash
        # perform the Bind operation
        if not c.bind():
            if c.result["description"] == "invalidCredentials":
                print('[-] Username or password is incorrect.')
            else:
                print('[-] Error in bind', c.result)
            sys.exit(1)
        else:
            print('[+] Connection established...')

        if self.operation == "getDomainInfo":
            self.getDomainInfo(c)

        elif self.operation == "sidToObject":
            sid = input('[*] SID of the object: ')
            if self.sidToObjectName(c, sid):
                print('[+] sAMAccountName: %s' % self.sidToObjectName(c, sid)[1])
                print('[+] Distinguised Name: %s' % self.sidToObjectName(c, sid)[0])

        elif self.operation == "getPasswordPolicy":
            self.getPasswordPolicy(c)
            
        elif self.operation == "getTrustInfo":
            self.getTrustInfo(c)

        elif self.operation == "getHosts":
            self.enumHosts(c)
           
        elif self.operation == "getDCs":
            self.getDomainControllers(c)
        
        elif self.operation == "getUsers":
            self.enumUsers(c)

        elif self.operation == "getGroups":
            self.enumGroups(c)

        elif self.operation == "userDescriptions":
            self.usersDescription(c)

        elif self.operation == "hostDescriptions":
            self.hostsDescription(c)
           
        elif self.operation == "getPasswordNotRequired":
            self.getPasswordNotRequired(c)        

        elif self.operation == "getGroupMembers":
            gName = input('[*] Group Name: ')
            self.groupMembers(c, gName)

        elif self.operation == "searchUser":
            sUser = input('[*] Username: ')
            self.searchUser(c, sUser)

        elif self.operation == "searchHost":
            sHost = input('[*] Hostname: ')
            self.searchHost(c, sHost)

        elif self.operation == "unconstrainedComputer":
            self.hostsUnconstrained(c)

        elif self.operation == "constrainedComputer":
            self.hostsConstrained(c)

        elif self.operation == "constrainedUser":
            self.userConstrained(c)

        elif self.operation == "unconstrainedUser":
            self.userUnconstrained(c)

        elif self.operation == "getRbcd":
            self.getRbcd(c)

        elif self.operation == "addUser":
            givenName = input('[*] First Name: ')
            sn = input('[*] Last Name: ')
            sAMAccountName = input('[*] sAMAccountName: ')
            self.addUser(c, givenName, sn, sAMAccountName)

        elif self.operation == "delUser":
            userDn = input('[*] Distinguished Name of User: ')
            self.delUser(c, userDn)

        elif self.operation == "getSpns":
            self.getSpns(c)

        elif self.operation == "setSpn":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            setSpnDn = input('[*] Distinguished Name: ')
            spnName = input('[*] Spn Name: ')
            self.setSpn(c, setSpnDn, spnName)

        elif self.operation == "unSetSpn":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            setSpnDn = input('[*] Distinguished Name: ')
            spnName = input('[*] Spn Name: ')
            self.unSetSpn(c, setSpnDn, spnName)

        elif self.operation == "addUnconstrained":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            unconstrainedDn = input('[*] Distinguished Name: ')
            self.addUnconstrained(c, unconstrainedDn)

        elif self.operation == "addConstrained":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            constrainedDn = input('[*] Target DN for adding Constrained Delegation: ')
            constrainedName = input('[*] To determine services to be delegated for a user or computer, search computer or user with a logon name: ')
            if constrainedDn and constrainedName:
                self.addConstrained(c, constrainedDn, constrainedName)
            else:
                print('[-] The specified values must not empty!')

        elif self.operation == "getAsRep":
            self.getAsRep(c)            
            
        elif self.operation == "addAsRepRoasting":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            asRepDn = input('[*] Distinguished Name: ')
            self.addAsRep(c, asRepDn)

        elif self.operation == "delAsRepRoasting":
            print('[*] Example DN: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            asRepDn = input('[*] Distinguished Name: ')
            self.delAsRep(c, asRepDn)

        elif self.operation == "addUserToGroup":
            print('[*] Example Group DN: cn=Domain Admins,cn=Users,' + self.searchBaseName)
            user_dn = input('[*] User Distinguished Name: ')
            group_dn = input('[*] Group Distinguished Name: ')
            self.addUserToGroup(c, user_dn, group_dn)

        elif self.operation == "resetObject":
            print('[*] Example CN: unsafe inline')
            objDn = input('[*] Object CN: ')
            self.resetObject(c, objDn)

        elif self.operation == "help" or self.operation == "?":
            usage.Helper()

        elif self.operation == "uacTable":
            uactable.userAccountControlTable()

        elif self.operation == "checkConnection":
            self.checkConnection(c)

        else:
            print('[-] Invalid operation name!')
            print('[!] Use exit or help to list commands!')

    def getDomainInfo(self, c):
        c.search(search_base=self.searchBaseName, search_filter='(objectClass=domain)', attributes=ALL_ATTRIBUTES)
        table = PrettyTable(['Domain Name', 'DN', 'SID', 'ms-DS-MachineAccountQuota', 'Domain Created Time'])
        table.align = "l"
        table.add_row([c.entries[0]['dc'], c.entries[0]['distinguishedName'], c.entries[0]['objectSid'], c.entries[0]['ms-DS-MachineAccountQuota'], c.entries[0]['whenCreated']])
        print(table)

    def getPasswordPolicy(self, c):
        c.search(search_base=self.searchBaseName, search_filter='(objectClass=domain)', attributes=ALL_ATTRIBUTES)
        columnLayout = ['Policy', 'Policy Setting']
        table = PrettyTable()
        table.add_column(columnLayout[0], ['Minimum password age (days)', 'Maximum password age (days)', 'Minimum password length', 'Length of password history maintained',
                             'Lockout threshold', 'Lockout duration (minutes)', 'Lockout observation window (minutes)'])
        table.add_column(columnLayout[1], [c.entries[0]['minPwdAge'], c.entries[0]['maxPwdAge'], c.entries[0]['minPwdLength'], c.entries[0]['pwdHistoryLength'], c.entries[0]['lockoutThreshold'],
                       c.entries[0]['lockoutDuration'], c.entries[0]['lockOutObservationWindow']])
        table.align = "l"
        print(table)        

    def getTrustInfo(self, c):
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName, search_filter='(objectClass=trustedDomain)', attributes=ALL_ATTRIBUTES, generator=True)
        table = PrettyTable(['Domain Name', 'Domain NetBios Name', 'SID', 'Trust Direction', 'When Created'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                createdTime = str(entry['attributes']['whenCreated']).split("+")[0]
                #converting sid value
                byteSid = entry['attributes']['securityIdentifier']
                sid = convertsid.sid_to_str(byteSid)
                #converting trustdirection
                trustValue = entry['attributes']['trustDirection']
                if trustValue == 3:
                    trustDirection = 'Bidirectional'
                elif trustValue == 2:
                    trustDirection = 'Outbound'
                elif trustValue == 1:
                    trustDirection = 'Inbound'
                elif trustValue == 0:
                    trustDirection = 'Disabled'
                else:
                    trustDirection = '[]'

                table.add_row([entry['attributes']['trustPartner'], entry['attributes']['flatName'], sid, trustDirection, createdTime])
                total_entries += 1
        if total_entries > 0:
                print(table)
                print('[+] Count of trust: ', total_entries)
        else:
            print('[-] Trust relationship is not defined!')        
            
    def enumHosts(self, c):
        # enum all hosts without DCs
        # domain controller: search_filter='(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(objectCategory=Computer)',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'operatingSystem', 'operatingSystemVersion', 'logonCount',
                                                                     'lastLogon'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Computers of " + self.domainName + " domain: \n")
        table = PrettyTable(['Computer Name', 'Operating System',  'Version', 'Logon Count', 'Last Logon Time'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['operatingSystem'],
                               entry['attributes']['operatingSystemVersion'], entry['attributes']['logonCount'], entry['attributes']['lastLogon']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of computers: ', total_entries)
        else:
            print('[-] Not found!')
            
    def getDomainControllers(self, c):
        # Get Domain Controllers
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'dNSHostName', 'operatingSystem',
                                                                     'operatingSystemVersion', 'distinguishedName'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Domain Controllers of " + self.domainName + " domain: \n")
        table = PrettyTable(['Computer Name', 'Dns Name', 'Operating System', 'Version', 'DN'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['dNSHostName'],
                               entry['attributes']['operatingSystem'], entry['attributes']['operatingSystemVersion'],
                               entry['attributes']['distinguishedName']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of DCs: ', total_entries)
        else:
            print('[-] Something went wrong!')            

    def enumUsers(self, c):
        # enum all users
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'sAMAccountName', 'userAccountControl',
                                                                     'logonCount', 'adminCount', 'lastLogon', 'pwdLastSet'])

        print("[*] Users of " + self.domainName + " domain: \n")
        table = PrettyTable(['Username', 'samAccountName', 'userAccountControl', 'Logon Count', 'Admin Count', 'Last Logon Time', 'Password Last Set'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                pwdLastTime = str(entry['attributes']['pwdLastSet']).split()
                lastLogonTime = str(entry['attributes']['lastLogon']).split(".")
                table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'],
                               entry['attributes']['userAccountControl'], entry['attributes']['logonCount'],
                               entry['attributes']['adminCount'], lastLogonTime[0], pwdLastTime[0]])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of users: ', total_entries)
        else:
            print('[-] Not found!')

    def enumGroups(self, c):
        # enum Groups
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(objectCategory=group)',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'distinguishedName', 'objectSid', 'description'])

        print("[*] Groups of " + self.domainName + " domain: \n")
        table = PrettyTable(['Name', 'Distinguished Name', 'Object SID', 'Description'])
        table._max_width = {"Distinguished Name": 70, "description": 70}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['distinguishedName'], entry['attributes']['objectSid'], entry['attributes']['description']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of groups: ', total_entries)
        else:
            print('[-] Not found!')

    def searchUser(self, c, sUser):
        # search user
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user)(|(cn=*' + sUser + '*)(sAMAccountName=*' + sUser + '*)))',
                                                         search_scope=SUBTREE,
                                                         attributes=['sAMAccountName', 'userAccountControl',
                                                                     'servicePrincipalName', 'logonCount', 'adminCount',
                                                                     'distinguishedName', 'memberOf', 'objectSid', 'lastLogon'])

        print("[*] Users of " + self.domainName + " domain: \n")
        table = PrettyTable(
            ['samAccountName', 'userAccountControl', 'servicePrincipalName', 'Logon Count', 'Admin Count',
             'Distinguished Name', 'Member Of', 'RID', 'Last Logon Time'])
        table._max_width = {"servicePrincipalName": 30, "Distinguished Name": 45, "Member Of": 45}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                memberOfs = entry['attributes']['memberOf']
                lastLogonTime = str(entry['attributes']['lastLogon']).split()
                rid = str(entry['attributes']['objectSid']).split('-')
                if len(memberOfs) > 0:
                    for memberOf in memberOfs:
                        table.add_row([entry['attributes']['sAMAccountName'], entry['attributes']['userAccountControl'],
                                       entry['attributes']['servicePrincipalName'], entry['attributes']['logonCount'],
                                       entry['attributes']['adminCount'], entry['attributes']['distinguishedName'],
                                       memberOf, rid[7], lastLogonTime[0]])
                else:
                    table.add_row([entry['attributes']['sAMAccountName'], entry['attributes']['userAccountControl'],
                                   entry['attributes']['servicePrincipalName'], entry['attributes']['logonCount'],
                                   entry['attributes']['adminCount'], entry['attributes']['distinguishedName'],
                                   '[]', rid[7], lastLogonTime[0]])

                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of searched domain users: ', total_entries)
        else:
            print('[-] Not found!')

    def searchHost(self, c, sHost):
        # search host
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=Computer)(cn=*' + sHost + '*))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'distinguishedName', 'operatingSystem', 'operatingSystemVersion',
                                                                     'userAccountControl', 'logonCount', 'lastLogon',
                                                                     'servicePrincipalName', 'objectSid'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Computers of " + self.domainName + " domain: \n")
        table = PrettyTable(
            ['Computer Name', 'Distinguished Name', 'Operating System', 'Version', 'userAccountControl', 'servicePrincipalName', 'Logon Count', 'RID', 'Last Logon Time'])
        table._max_width = {"servicePrincipalName": 40, "Distinguished Name": 40, "Operating System": 25}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                lastLogonTime = str(entry['attributes']['lastLogon']).split(".")
                rid = str(entry['attributes']['objectSid']).split('-')
                table.add_row([entry['attributes']['cn'], entry['attributes']['distinguishedName'], entry['attributes']['operatingSystem'],
                               entry['attributes']['operatingSystemVersion'], entry['attributes']['userAccountControl'], entry['attributes']['servicePrincipalName'],
                               entry['attributes']['logonCount'], rid[7], lastLogonTime[0]])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of searched computers: ', total_entries)
        else:
            print('[-] Not found!')

        if total_entries > 0:
            return entry['attributes']['servicePrincipalName']

    def groupMembers(self, c, gName):
        # enum group member and memberOfs
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=group)(cn=*' + gName + '*))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'member', 'memberOf', 'adminCount'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Groups of " + self.domainName + " domain: \n")
        table = PrettyTable(['Name', 'Member', 'Member Of', 'Admin Count'])
        table._max_width = {"Member": 70, "Member Of": 70}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                memberOfs = entry['attributes']['memberOf']
                members = entry['attributes']['member']
                if len(memberOfs) > 0:
                    for memberOf in memberOfs:
                        if len(members) > 0:
                            for member in members:
                                table.add_row([entry['attributes']['cn'], member, memberOf, entry['attributes']['adminCount']])
                                total_entries += 1
                        else:
                            table.add_row(entry['attributes']['cn'], '[]', memberOf, entry['attributes']['adminCount'])
                            total_entries += 1
                else:
                    if len(members) > 0:
                        for member in members:
                            table.add_row([entry['attributes']['cn'], member, '[]', entry['attributes']['adminCount']])
                            total_entries += 1
                    else:
                        table.add_row([entry['attributes']['cn'], '[]', '[]', entry['attributes']['adminCount']])
                        total_entries += 1

        if total_entries > 0:
            print(table)
            print('[+] Count of searched groups: ', total_entries)
        else:
            print('[-] Not found!')

    def usersDescription(self, c):
        # enum all descriptions of users
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'sAMAccountName', 'description'])

        print("[*] Users of " + self.domainName + " domain: \n")
        table = PrettyTable(['Username', 'samAccountName', 'Description'])
        table._max_width = {"Description": 70}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'],
                               entry['attributes']['description']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of domain users: ', total_entries)
        else:
            print('[-] Not found!')

    def hostsDescription(self, c):
        # enum all descriptions of computers
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(objectCategory=Computer)',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'description'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Computers of " + self.domainName + " domain: \n")
        table = PrettyTable(['Computer Name', 'Description'])
        table._max_width = {"Description": 70}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['description']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of computers: ', total_entries)
        else:
            print('[-] Not found!')

    def getPasswordNotRequired(self, c):
        # All users not required to have a password. (All possible users that don't have a password.)
        # If a password is set later for the user, the UAC value is not changed. Hence, this LDAP query can return a user that is set a password.
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))',
                                                         search_scope=SUBTREE,
                                                         attributes=['sAMAccountName', 'memberOf', 'distinguishedName',
                                                                     'description', 'userAccountControl'])

        print("[*] All users not required to have a password: \n")
        table = PrettyTable(['sAMAccountName', 'Member Of', 'DN', 'Description', 'userAccountControl'])
        table._max_width = {"Member Of": 70, "DN": 70, "Description": 60}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                memberOfs = entry['attributes']['memberOf']
                if len(memberOfs) > 0:
                    for memberOf in memberOfs:
                        table.add_row(
                            [entry['attributes']['sAMAccountName'], memberOf, entry['attributes']['distinguishedName'],
                             entry['attributes']['description'], entry['attributes']['userAccountControl']])
                else:
                    table.add_row(
                        [entry['attributes']['sAMAccountName'], '[]', entry['attributes']['distinguishedName'],
                         entry['attributes']['description'], entry['attributes']['userAccountControl']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of searched domain users: ', total_entries)
        else:
            print('[-] Not found')
            
    def hostsUnconstrained(self, c):
        # domain controller: search_filter='(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))'
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'operatingSystem', 'userAccountControl',
                                                                     'logonCount', 'lastLogon'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Unconstrained Delegation Computers of " + self.domainName + " domain: \n")
        table = PrettyTable(
            ['Computer Name', 'Operating System', 'userAccountControl', 'Logon Count', 'Last Logon Time'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['operatingSystem'],
                               entry['attributes']['userAccountControl'], entry['attributes']['logonCount'],
                               entry['attributes']['lastLogon']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of computers: ', total_entries)
        else:
            print('[-] Not found!')

    def hostsConstrained(self, c):
        # Querying ALL Hosts with "Trusted For Delegation To Specific Services – Any AuthN
        # (&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*))
        # Trusted For Delegation To Specific Services – Kerberos AuthN
        # (&(!(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)))(msDS-AllowedToDelegateTo=*))
        # And Computer Object
        # (&(objectCategory=Computer))
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(|(&(!(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)))(msDS-AllowedToDelegateTo=*))(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)))(objectCategory=computer))',
                                                         search_scope=SUBTREE,
                                                         attributes=['sAMAccountName', 'userAccountControl',
                                                                     'msDS-AllowedToDelegateTo'])

        print("[*] Constrained Hosts of " + self.domainName + " domain: \n")
        print("[*] Querying ALL Hosts with trusted for delegation to specific services (any auth or kerberos)...")
        table = PrettyTable(['samAccountName', 'userAccountControl', 'AllowedToDelegateTo'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                # print("[+] Username: " + entry['attributes']['sAMAccountName'] + " || SPN: " + str(entry['attributes']['servicePrincipalName']) + " || AllowedToDelegateTo: " + str(entry['attributes']['msDS-AllowedToDelegateTo']))
                services = entry['attributes']['msDS-AllowedToDelegateTo']
                for service in services:
                    table.add_row(
                        [entry['attributes']['sAMAccountName'], entry['attributes']['userAccountControl'], service])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of computers: ', total_entries)
        else:
            print('[-] Not found!')

    def userConstrained(self, c):
        # Querying ALL Users with "Trusted For Delegation To Specific Services – Any AuthN
        # (&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*))
        # Trusted For Delegation To Specific Services – Kerberos AuthN
        # (&(!(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)))(msDS-AllowedToDelegateTo=*))
        # And Person Object
        # (&(objectCategory=person))
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(|(&(!(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216)))(msDS-AllowedToDelegateTo=*))(&(userAccountControl:1.2.840.113556.1.4.803:=16777216)(msDS-AllowedToDelegateTo=*)))(objectCategory=person))',
                                                         search_scope=SUBTREE,
                                                         attributes=['sAMAccountName', 'servicePrincipalName',
                                                                     'msDS-AllowedToDelegateTo'])

        print("[*] Constrained Users of " + self.domainName + " domain: \n")
        print("[*] Querying ALL Users with trusted for delegation to specific services (any auth or kerberos)...")
        table = PrettyTable(['samAccountName', 'servicePrincipalName', 'AllowedToDelegateTo'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                services = entry['attributes']['msDS-AllowedToDelegateTo']
                for service in services:
                    table.add_row(
                        [entry['attributes']['sAMAccountName'], entry['attributes']['servicePrincipalName'], service])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of domain users: ', total_entries)
        else:
            print('[-] Not found!')

    def userUnconstrained(self, c):
        # Querying ALL Users with "Trusted For Delegation To Any Service (Kerberos Only)
        # (userAccountControl:1.2.840.113556.1.4.803:=524288)

        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))',
                                                         search_scope=SUBTREE,
                                                         attributes=['sAMAccountName', 'servicePrincipalName'])

        print("[*] Unconstrained Users of " + self.domainName + " domain: \n")
        print("[*] Querying ALL Users with trusted for delegation to any service (kerberos only)...")
        table = PrettyTable(['Username', 'samAccountName', 'servicePrincipalName'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'], entry['attributes']['servicePrincipalName']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of domain users: ', total_entries)
        else:
            print('[-] Not found!')

    def getRbcd(self, c):
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(|(objectCategory=computer)(objectCategory=person)))',
                                                         search_scope=SUBTREE,
                                                         attributes=ALL_ATTRIBUTES,
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Resource-based constrained delegation configuration for " + self.domainName + " domain: \n")
        table = PrettyTable(['Resource Name', 'Accounts allowed to act on behalf of other identity', 'Accounts Distinguished Name'])
        table._max_width = {"Accounts Distinguished Name": 80}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                sd = ldaptypes.SR_SECURITY_DESCRIPTOR(
                    data=entry['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
                if len(sd['Dacl'].aces) > 0:
                    for ace in sd['Dacl'].aces:
                        sid = ace['Ace']['Sid'].formatCanonical()
                        #sid to object name and distinguishedName
                        objectName = self.sidToObjectName(c, sid)[1]
                        dn = self.sidToObjectName(c, sid)[0]
                        table.add_row([entry['attributes']['sAMAccountName'], objectName, dn])
                        total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of accounts: ', total_entries)
        else:
            print('[-] Not found!')

    def addUser(self, c, givenName, sn, sAMAccountName):
        addUserDn = 'cn=' + givenName + ' ' + sn + ',cn=Users,' + self.searchBaseName
        c.add(addUserDn, 'inetOrgPerson', {'givenName': givenName, 'sn': sn, 'sAMAccountName': sAMAccountName,
                                           'userPrincipalName': sAMAccountName + '@' + self.domainName})
        c.modify(addUserDn, {'userAccountControl': (MODIFY_REPLACE, [544])})
        if c.result['description'] == 'success':
            print('[+] ' + sAMAccountName + ' is added!')
            print('[+] Distinguished Name: ' + addUserDn)
            print('[!] User must change password at next logon.')
        else:
            print('[!] Are you sure that you have adding user permission?')
            print('[!] If yes, please provide Distinguished Name additionaly')
            print('[*] Example: cn=unsafe inline,cn=Users,' + self.searchBaseName)
            addUserDn = input('[*] Distinguished Name: ')
            givenName = input('[*] First Name: ')
            sn = input('[*] Last Name: ')
            sAMAccountName = input('[*] sAMAccountName: ')
            c.add(addUserDn, 'inetOrgPerson', {'givenName': givenName, 'sn': sn, 'sAMAccountName': sAMAccountName,
                                               'userPrincipalName': sAMAccountName + '@' + self.domainName})
            c.modify(addUserDn, {'userAccountControl': (MODIFY_REPLACE, [544])})
            if c.result['description'] == 'success':
                print('[+] ' + sAMAccountName + ' is added!')
                print('[+] Distinguished Name: ' + addUserDn)
                print('[!] User must change password at next logon.')
            else:
                print('[-] ' + sAMAccountName + ' is not added!')
                print('[!] ' + c.result['message'])

    def addUserToGroup(self, c, user_dn, group_dn):
        result = addUserToGroups(c, user_dn, group_dn)
        if result is True:
            print('[+] ' + user_dn + ' was added to ' + group_dn)
        else:
            print('[-] User was not added to ' + group_dn)
            print('[!] ' + c.result['message'])

    def delUser(self, c, userDn):
        c.delete(userDn)
        if c.result['description'] == 'success':
            print('[+] ' + userDn + ' is deleted.')
        elif c.result['description'] == 'noSuchObject':
            print('[-] No such object! ' + userDn)
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] ' + userDn + ' is not deleted!')
            print('[!] ' + c.result['message'])

    def getSpns(self, c):
        # Getting all user SPNs for the kerberoasting attack. The krbtgt account is excluded.
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))(!(sAMAccountName=krbtgt)))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'sAMAccountName', 'servicePrincipalName'])

        table = PrettyTable(['Name', 'sAMAccountName', 'servicePrincipalName'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'],
                               entry['attributes']['servicePrincipalName']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of SPNs: ', total_entries)
        else:
            print('[-] Not found Kerberoastable user!')

    def setSpn(self, c, setSpnDn, spnName):
        c.modify(setSpnDn, {'servicePrincipalName': [(MODIFY_ADD, [spnName])]})
        if c.result['result'] == 32:
            print('[-] Object is not found! Distinguished name is wrong.')
        elif c.result['result'] == 19:
            print('[-] SPN format is invalid.')
            print('[!] ' + c.result['message'])
        elif c.result['result'] == 20:
            print('[-] SPN is duplicated.')
            print('[!] ' + c.result['message'])
        elif c.result['result'] == 0:
            print('[+] ' + spnName + ' is added.')
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] Something went wrong!')
            print('[!] ' + c.result['message'])

    def unSetSpn(self, c, setSpnDn, spnName):
        c.modify(setSpnDn, {'servicePrincipalName': [(MODIFY_DELETE, [spnName])]})
        if c.result['result'] == 32:
            print('[-] Object is not found! Distinguished name is wrong.')
        elif c.result['result'] == 19:
            print('[-] SPN format is invalid.')
            print('[!] ' + c.result['message'])
        elif c.result['result'] == 16:
            print('[-] No such attribute. The SPN is wrong!')
            print('[!] ' + c.result['message'])
        elif c.result['result'] == 0:
            print('[+] ' + spnName + ' is deleted.')
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] Something went wrong!')
            print('[!] ' + c.result['message'])

    def addUnconstrained(self, c, unconstrainedDn):
        # userAccountControl 524288 TRUSTED_FOR_DELEGATION
        c.modify(unconstrainedDn, {'userAccountControl': [(MODIFY_REPLACE, [524288])]})
        if c.result['description'] == 'success':
            print('[+] Trust this ' + unconstrainedDn + ' for delegation to any service(Kerberos only)')
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] Something went wrong!')
            print('[!] ' + c.result['message'])

    def addConstrained(self, c, constrainedDn, constrainedName):
        # userAccountControl 512 NORMAL_ACCOUNT
        # userAccountControl 16777216 TRUSTED_TO_AUTH_FOR_DELEGATION
        c.search(search_base=self.searchBaseName, search_filter='(&(servicePrincipalName=*)(sAMAccountName=*%s*))' % constrainedName, attributes=ALL_ATTRIBUTES)
        if len(c.entries) > 0:
            services = c.entries[0]['servicePrincipalName']
            table = PrettyTable(['Account Name','SPNs of Computer/User'])
            table.align = "l"
            for service in services:
                table.add_row([c.entries[0]['sAMAccountName'],service])
            print(table)
            print('[*] Trust this user/computer for delegation to specified services only.')
            allowedToDelegateTo = input('[*] Specify services to which "%s" account can present delegated credentials (comma separated): ' % constrainedDn)
            formattedAllowedToDelegateTo = allowedToDelegateTo.split(',')
            c.modify(constrainedDn, {'userAccountControl': [(MODIFY_REPLACE, [16777728])]})
            c.modify(constrainedDn, {'msDS-AllowedToDelegateTo': [(MODIFY_ADD, formattedAllowedToDelegateTo)]})

            if c.result['description'] == 'noSuchObject':
                print('[-] No such object like: ' + constrainedDn)
            elif c.result['description'] == 'success':
                print('[+] Constrained delegation is added for ' + constrainedDn)
            elif c.result['description'] == 'insufficientAccessRights':
                print('[-] Access is denied!')
            elif c.result['description'] == 'attributeOrValueExists':
                print('[!] Attribute or value had been added already.')
            else:
                print('[-] Something went wrong!')
                print('[!] ' + c.result['message'])

        else:
            print('[-] The Computer/User account was not found or the specified user has not a SPN!')

    def getAsRep(self, c):
        # Getting all users for the ASREProasting attack.
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))',
                                                         search_scope=SUBTREE,
                                                         attributes=['cn', 'sAMAccountName', 'memberOf', 'distinguishedName'])

        table = PrettyTable(['Name', 'sAMAccountName', 'Member Of', 'DN'])
        table._max_width = {"Member Of": 80, "DN": 80}
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                memberOfs = entry['attributes']['memberOf']
                if len(memberOfs) > 0:
                    for memberOf in memberOfs:
                        table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'], memberOf, entry['attributes']['distinguishedName']])
                else:
                    table.add_row([entry['attributes']['cn'], entry['attributes']['sAMAccountName'], '[]', entry['attributes']['distinguishedName']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of searched domain users: ', total_entries)
        else:
            print('[-] Not found ASREProastable user!')
            
    def addAsRep(self, c, asRepDn):
        # userAccountControl 4194304 DONT_REQ_PREAUTH
        # userAccountControl 512 NORMAL_ACCOUNT
        c.modify(asRepDn, {'userAccountControl': [(MODIFY_REPLACE, [4194816])]})
        if c.result['description'] == 'success':
            print('[+] Do not require Kerberos preauthentication for ' + asRepDn)
            print('[+] AS-REP Roasting attack must be possible.')
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] Something went wrong!')
            print('[!] ' + str(c.result))

    def delAsRep(self, c, asRepDn):
        # userAccountControl 4194304 DONT_REQ_PREAUTH
        # userAccountControl 512 NORMAL_ACCOUNT
        c.modify(asRepDn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
        if c.result['description'] == 'success':
            print('[+] Kerberos preauthentication is required for ' + asRepDn)
            print('[+] AS-REP Roasting attack must not be possible.')
        elif c.result['description'] == 'insufficientAccessRights':
            print('[-] Access is denied!')
        else:
            print('[-] Something went wrong!')
            print('[!] ' + str(c.result))

    def checkConnection(self, c):
        table = PrettyTable(['Connection Details'])
        table.add_row([str(c)])
        print(table)

    def sidToObjectName(self, c, sid):
        c.search(search_base=self.searchBaseName, search_filter='(objectSID=%s)' % sid, attributes=['sAMAccountName', 'distinguishedName'])
        try:
            objectName = c.entries[0]['sAMAccountName']
            dn = c.entries[0]['distinguishedName']
            return dn, objectName
        except:
            print('[-] SID not found: ', sid)
            return False

    def resetObject(self, c, objDn):
        # for restoring userAccountControl value of object that has been modified
        total_entries = 0
        entry_generator = c.extend.standard.paged_search(search_base=self.searchBaseName,
                                                         search_filter='(&(objectClass=user)(cn=*' + objDn + '*))',
                                                         search_scope=SUBTREE,
                                                         attributes=['distinguishedName', 'sAMAccountName',
                                                                     'userAccountControl'],
                                                         paged_size=None,
                                                         generator=True)

        print("[*] Computers/users of " + self.domainName + " domain: \n")
        table = PrettyTable(['Distinguished Name', 'sAMAccountName', 'userAccountControl'])
        table.align = "l"
        for entry in entry_generator:
            if 'dn' in entry:
                table.add_row([entry['attributes']['distinguishedName'], entry['attributes']['sAMAccountName'],
                               entry['attributes']['userAccountControl']])
                total_entries += 1
        if total_entries > 0:
            print(table)
            print('[+] Count of searched objects: ', total_entries)
        else:
            print('[-] Not found!')

        if total_entries == 1:
            oldUserAccountControl = entry['attributes']['userAccountControl']
            dName = entry['attributes']['distinguishedName']
            table = PrettyTable(['userAccountControl'])
            table.align = "l"
            table.add_row([str(oldUserAccountControl)])
            print(table)

            response = input('[*] Would you like to change value of userAccountControl?(y/n) ')
            if response == 'y':
                newUserAccountControl = input('[*] userAccountControl Value: ')
                c.modify(dName, {'userAccountControl': [(MODIFY_REPLACE, [newUserAccountControl])]})
                if c.result['description'] == 'success':
                    table = PrettyTable(['DN', 'userAccountControl'])
                    table.align = "l"
                    table.add_row([dName, newUserAccountControl])
                    print(table)
                else:
                    print('[-] Something went wrong!')
                    print('[!] ' + str(c.result))
        else:
            print('[!] To change value of userAccountControl you must specify one user/computer account!')


count = 0
while True:
    try:
        # to avoid exiting after an operation based error
        if count == 0:
            # print banner
            banner.dumlupinar()
            server = input('[*] IP address of DC: ')
            domainName = input('[*] Domain name: ')
            username = input('[*] Username: ')
            password = getpass.getpass(prompt='[*] Password or NT Hash: ', stream=None)
            # Getting searchbase name
            searchBase = domainName.split('.')
            size = len(searchBase)
            if size < 2:
                print("[-] Provide domain's DNS name! Example: unsafe.local")
                continue
            elif size < 3:
                searchBaseName = 'DC=' + searchBase[0] + ',DC=' + searchBase[1]
            elif size < 4:
                searchBaseName = 'DC=' + searchBase[0] + ',DC=' + searchBase[1] + ',DC=' + searchBase[2]
            elif size < 5:
                searchBaseName = 'DC=' + searchBase[0] + ',DC=' + searchBase[1] + ',DC=' + searchBase[2] + ',DC=' + \
                                 searchBase[3]
            elif size < 6:
                searchBaseName = 'DC=' + searchBase[0] + ',DC=' + searchBase[1] + ',DC=' + searchBase[2] + ',DC=' + \
                                 searchBase[3] + ',DC=' + searchBase[4]
            else:
                print("[-] Unexpected domain name!")
                sys.exit(1)

            if not server:
                print("[-] IP address of DC is required!")
                continue

            if not password or not username:
                print("[-] Password/NT Hash or username is required!")
                continue
        count += 1
        while (count > 0):
            operation = input(Style.BRIGHT + username + '@' + domainName + ':~$ ' + Style.RESET_ALL)
            # to exit an error loop
            if operation == "exit":
                print('[*] Exiting...')
                sys.exit(0)
            dumlupinar = dcDumlu(server, domainName, username, password, operation, searchBaseName)
            dumlupinar.main()

    except KeyboardInterrupt:
        print('\n[-] Exiting...')
        sys.exit(0)

    except socket.error as err:
        print('[-] Connection error, check that the target server is up or your network connection: ' + str(err))
        print('[!] For exiting the script, please type exit or press ctrl+c')
        continue

    except Exception as err:
        print('[-] ' + str(err))
        print('[!] For exiting the script, please type exit or press ctrl+c')
        continue
