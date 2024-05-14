import logging

logging.basicConfig(filename='output.log', encoding='utf-8', level=logging.INFO, format='%(asctime)s - %(levelname)s : \n%(message)s')

def logOperation(operation, result):
    logging.info('LDAP %s operation result: \n%s' % (operation,result))
