from prettytable import PrettyTable

def userAccountControlTable():

    uacTable = PrettyTable(["Property Flag", "Value in Hexadecimal", "Value in Decimal"])
    uacTable.add_row(["SCRIPT","0x0001","1"])
    uacTable.add_row(["ACCOUNTDISABLE","0x0002","2"])
    uacTable.add_row(["HOMEDIR_REQUIRED","0x0008","8"])
    uacTable.add_row(["LOCKOUT","0x0010","16"])
    uacTable.add_row(["PASSWD_NOTREQD","0x0020","32"])
    uacTable.add_row(["PASSWD_CANT_CHANGE","0x0040","64"])
    uacTable.add_row(["ENCRYPTED_TEXT_PWD_ALLOWED","0x0080","128"])
    uacTable.add_row(["TEMP_DUPLICATE_ACCOUNT","0x0100","256"])
    uacTable.add_row(["NORMAL_ACCOUNT","0x0200","512"])
    uacTable.add_row(["INTERDOMAIN_TRUST_ACCOUNT","0x0800","2048"])
    uacTable.add_row(["WORKSTATION_TRUST_ACCOUNT","0x1000","4096"])
    uacTable.add_row(["SERVER_TRUST_ACCOUNT","0x2000","8192"])
    uacTable.add_row(["DONT_EXPIRE_PASSWORD","0x10000","65536"])
    uacTable.add_row(["MNS_LOGON_ACCOUNT","0x20000","131072"])
    uacTable.add_row(["SMARTCARD_REQUIRED","0x40000","262144"])
    uacTable.add_row(["TRUSTED_FOR_DELEGATION","0x80000","524288"])
    uacTable.add_row(["NOT_DELEGATED","0x100000","1048576"])
    uacTable.add_row(["USE_DES_KEY_ONLY","0x200000","2097152"])
    uacTable.add_row(["DONT_REQ_PREAUTH","0x400000","4194304"])
    uacTable.add_row(["PASSWORD_EXPIRED","0x800000","8388608"])
    uacTable.add_row(["TRUSTED_TO_AUTH_FOR_DELEGATION","0x1000000","16777216"])
    uacTable.add_row(["PARTIAL_SECRETS_ACCOUNT","0x04000000","67108864"])

    print(uacTable)