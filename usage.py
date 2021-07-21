from prettytable import PrettyTable

def Helper():
    helpTable = PrettyTable(["Commands", "Descriptions"])
    helpTable.align = "l"
    helpTable.add_row(["getHosts","Dump hosts information"])
    helpTable.add_row(["getUsers", "Dump users information"])
    helpTable.add_row(["getGroups", "Dump groups information"])
    helpTable.add_row(["hostDescriptions", "Dump description of hosts information"])
    helpTable.add_row(["userDescriptions", "Dump description of users information"])
    helpTable.add_row(["getGroupMembers", "Dump members of specified group"])
    helpTable.add_row(["searchUser", "Search specific user"])
    helpTable.add_row(["searchHost", "Search specific host"])
    helpTable.add_row(["unconstrainedComputer", "Enumerate unconstrained computer account"])
    helpTable.add_row(["constrainedComputer", "Enumerate constrained computer account"])
    helpTable.add_row(["constrainedUser", "Enumerate constrained user account"])
    helpTable.add_row(["unconstrainedUser", "Enumerate unconstrained user account"])
    helpTable.add_row(["addUser", "Add a user"])
    helpTable.add_row(["addUserToGroup", "Add a user to group"])
    helpTable.add_row(["delUser", "Delete a user"])
    helpTable.add_row(["setSpn", " Set a servicePrincipalName attribute"])
    helpTable.add_row(["unSetSpn", "Unset a servicePrincipalName attribute"])
    helpTable.add_row(["addUnconstrained", "Modify an object for delegation to any service with Kerberos Auth."])
    helpTable.add_row(["addConstrained", "Modify an object for delegation to specific service"])
    helpTable.add_row(["addAsRepRoasting", "Set user option as do not require Kerberos preauthentication for As-Rep Roasting attack"])
    helpTable.add_row(["delAsRepRoasting", "Set user option as Kerberos preauthentication is required"])
    helpTable.add_row(["resetObject", "Change userAccountControl attribute of object to reset modifications that are Kerberos delegation attacks"])
    helpTable.add_row(["uacTable", "Show values fo userAccountControl attribute if you need for resetObject operation"])
    helpTable.add_row(["help", "Print usage"])
    helpTable.add_row(["exit", "Exit"])
    print(helpTable)