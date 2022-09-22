#reference:
#https://stackoverflow.com/questions/33188413/python-code-to-convert-from-objectsid-to-sid-representation

def sid_to_str(sid):

    try:
        if str is not bytes:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
            # If true then it is represented in hex
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])

        objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority
        return objectSid

    except Exception as e:
        print('[-] ' + e)

    return sid
