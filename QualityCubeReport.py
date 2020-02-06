import json
from http.client import HTTPSConnection
from http.client import HTTPConnection
from base64 import b64encode
import argparse
import logging
import logging.handlers
import re
import sys
import csv
import traceback
import datetime

########################################################################
# Class containing all the attributed to be sent to the CSV file

class QualityCubeItem:
 
    # Class attributes
    metricId = None
    metricName = None
    critical = False
    
    # type possible values = quality-rules / technical-criteria / quality-distributions
    type = None
    
    # parentType possible values = platform / extension
    parentType = None
    parentName = None
    parentVersion = None
    lastVersion = False
    
    # Rest URI
    restHref = ''

    # list of technologies(C#, JEE ...)       
    listTechnologies = []
    
    # list of standard (CWE, ...)
    listQualityStandards = []

    # list of business criteria)
    listBusinessCriteria = []
    
    # list of Technical criteria
    listTechnicalCriteria = []  
    
    # list of parameters
    listParameters = []

    # list of standard
    threshold1 = -1
    threshold2 = -1
    threshold3 = -1
    threshold4 = -1
    
    #TODO
    technicalCriterionId = None
    technicalCriterionName = None
    weight = None
    businessCriterionId  = None
    businessCriterionName = None
    weightTechnicalCriterion = None    
    
    
    
    def __init__(self):
        None
    
    
    def add_technology(self,technology):
        if self.listTechnologies != None:
            self.listTechnologies.append(technology)
    
    def add_qualitystandard(self,standard):
        if self.listQualityStandards != None:
            self.listQualityStandards.append(standard)

    def add_businesscriterion(self,bc):
        if self.listBusinessCriteria != None:
            self.listBusinessCriteria.append(bc)

    def add_technicalcriterion(self,tc):
        if self.listTechnicalCriteria != None:
            self.listTechnicalCriteria.append(tc)
    
    def add_parameter(self, param):
        if self.listParameters != None:
            self.listParameters.append(param)
    
    
    def get_full_restHref(self):
        if self.restHref != None and self.restHref != '':
            return "https://technologies.castsoftware.com/rest" + self.restHref
        return ''

########################################################################
# retrieve the HTTPS connection

def get_connection(logger,host,protocol):
    logger.debug('get connection')
    connection = None
    if re.search('[hH][tT][tT][pP][sS]',protocol):
        connection = HTTPSConnection(host)
    elif re.search('[hH][tT][tT][pP]',protocol):
        connection = HTTPConnection(host)
    return connection

########################################################################
# execute Rest API request 

def execute_request(logger, connection, request):
    #we need to base 64 encode it 
    #and then decode it to acsii as python 3 stores it as a byte string
    #userAndPass = b64encode(user_password).decode("ascii")
    auth = str.encode("%s:%s" % (None, None))
    #user_and_pass = b64encode(auth).decode("ascii")
    user_and_pass = b64encode(auth).decode("iso-8859-1")
    headers = { 'Authorization' : 'Basic %s' %  user_and_pass , "accept" : "application/json"}

    request_text = "/rest" + request
    logger.debug('Sending request ' + request_text )   

    connection.request('GET', request_text, headers=headers)
    #get the response back
    response = connection.getresponse()
    logger.debug('Response status ' + str(response.status) + ' ' + str(response.reason))
    
    ResponseStatusSuccess = True
    # Status not 200
    if  response.status != 200:
        ResponseStatusSuccess = False
        msg = 'HTTPS request failed ' + str(response.status) + ' ' + str(response.reason)
        print (msg)
        logger.warning(msg)
    
    #send back the date
    #encoding = response.info().get_content_charset('utf-8')
    encoding = response.info().get_content_charset('iso-8859-1')
    responseread_decoded = response.read().decode(encoding)
    
    if not ResponseStatusSuccess:
        return None
    
    #print (responseread_decoded) 
    output_json_snapshots_loc = json.loads(responseread_decoded)
    
    return output_json_snapshots_loc


########################################################################
# for debugging


def log_qci(logger, qci):
    #msg = "Type;Parent;Version;Last version;Quality rule id;Quality rule name;Critical;Technologies;Href;Standards;Business criteria contribution;Technical criteria contribution;Rest Href"
    
    #Href
    msg = qci.parentType + ";" + qci.parentName + ";" + qci.parentVersion + ";" + str(qci.lastVersion) + ";" + str(qci.metricId) + ";" + qci.metricName + ";" + str(qci.critical) + ";"

    # List of technologies
    listtec = ''
    for tec in qci.listTechnologies:
        listtec += tec + '/'
    if listtec != '': listtec = listtec[:-1]
    msg += listtec + ';'  
    
    # href
    href = 'https://technologies.castsoftware.com/rules?s=' + str(qci.metricId) + '|qualityrules|' + str(qci.metricId) 
    msg += href + ';'
    
    # List of quality standards
    listqs = ''
    for qs in qci.listQualityStandards:
        listqs += qs + '/'
    if listqs != '': listqs = listqs[:-1]        
    msg += listqs + ';' 
 
    
    # List of business criteria
    listbc = ''
    for hf in qci.listBusinessCriteria:
        listbc += hf + '/'
    if listbc != '': listbc = listbc[:-1]        
    msg += listbc + ';'    
    
    # List of technical criteria
    listtc = ''
    for tc in qci.listTechnicalCriteria:
        listtc += tc + '/'
    if listtc != '': listtc = listtc[:-1]
    msg += listtc + ';'     
    
    # Rest Href
    msg += qci.get_full_restHref()
    
    print(msg)    
    
########################################################################
# Format to dict for the ouput into CSV line
    
    
def qci_to_dictitem(logger, qci):

    # List of technologies
    listtec = ''
    for tec in qci.listTechnologies:
        listtec += tec + '/'
    if listtec != '': listtec = listtec[:-1]
    
    # href
    href = 'https://technologies.castsoftware.com/rules?s=' + str(qci.metricId) + '|qualityrules|' + str(qci.metricId) 
    
    # List of quality standards
    listqs = ''
    for qs in qci.listQualityStandards:
        listqs += qs + '/'
    if listqs != '': listqs = listqs[:-1]        
 
    
    # List of business criteria
    listbc = ''
    for hf in qci.listBusinessCriteria:
        listbc += hf + '/'
    if listbc != '': listbc = listbc[:-1]        
    
    # List of technical criteria
    listtc = ''
    for tc in qci.listTechnicalCriteria:
        listtc += tc + '/'
    if listtc != '': listtc = listtc[:-1]

    return [qci.parentType, qci.parentName,  qci.parentVersion, str(qci.lastVersion), str(qci.metricId), qci.metricName,  str(qci.critical), listtec, href, listqs, listbc, listtc, qci.get_full_restHref()]

########################################################################
def get_platform_versions(logger, connection):
    request = "/AIP/versions"
    return execute_request(logger, connection, request)

########################################################################
def get_platform_version_qualityrules(logger, connection, platformversion):
    request = "/AIP/versions/" + platformversion + "/quality-rules"
    return execute_request(logger, connection, request)

########################################################################
def get_extensions(logger, connection):
    request = "/AIP/extensions"
    return execute_request(logger, connection, request)

########################################################################
def get_extensions_versions(logger, connection, extension):
    request = "/AIP/extensions/" + extension + '/versions'
    return execute_request(logger, connection, request)

########################################################################
def get_extensions_versions_qualityrules(logger, connection, extension, version):
    request = "/AIP/extensions/" + extension + '/versions/'+ version + '/quality-rules'
    return execute_request(logger, connection, request)

########################################################################
# intialize the command line arguments

def init_parse_argument():
    # get arguments
    parser = argparse.ArgumentParser(add_help=False)
    requiredNamed = parser.add_argument_group('Required named arguments')
    requiredNamed.add_argument('-versionFilter', required=False, dest='versionFilter', help='Platform and extension versions to selection (LAST|ALL')
    requiredNamed.add_argument('-detailLevel', required=False, dest='detailLevel', help='Level of detail (Simple/Intermediate/Full)')
    requiredNamed.add_argument('-log', required=True, dest='log', help='log file')
    
    return parser

########################################################################
# parse the quality rule json

def parse_jsonqr(logger, connection, json_qr, index, detailLevel):
    x = QualityCubeItem()
    x.listBusinessCriteria = []
    x.listParameters = []
    x.listQualityStandards = []
    x.listTechnicalCriteria = []
    x.listTechnologies = []
   
    href = json_qr['href'] 
    x.restHref = ''
    if href != None: 
        x.restHref = '/' + href 
    x.metricId = json_qr['id']
    x.metricName = json_qr['name']
    x.critical = json_qr['critical']
    x.type = 'quality-rules'
    
    # Last version for the platform or extension
    if index == 1:
        x.lastVersion = True
    
    # list of technologies
    for tech in json_qr['technologyNames']:
        x.add_technology(tech)
    
    # thresholds
    #x.threshold1 = json_qr['thresholds'][0]
    
    
    # we look at the quality rules details only if parameter lookupQualityRuleDetails has true value, because it's very time consuming
    # we do that only for the last version, but we don't have history for those data 
    if detailLevel != 'Simple' and x.lastVersion and x.restHref != None and x.restHref != '':
        json_qrdetail = execute_request(logger, connection,  x.restHref)
        for bc in json_qrdetail['businessCriteria']:
            x.add_businesscriterion(bc['name'])
        for tc in json_qrdetail['technicalCriteria']:
            x.add_technicalcriterion(tc['name'])
        for qs in json_qrdetail['qualityStandards']:
            x.add_qualitystandard(qs['standard'] + "/" + qs['id'])       
        for param in json_qrdetail['parameters']:
            x.add_parameter(param['name'])
             
    
    return x


######################################################################################################################
# Format a timestamp date into a string

def get_formatted_dateandtime(mydate):
    formatteddate = str(mydate.year) + "_"
    if mydate.month < 10:
        formatteddate += "0"
    formatteddate += str(mydate.month) + "_"
    if mydate.day < 10:
        formatteddate += "0"
    formatteddate += str(mydate.day)
    
    formatteddate += "_" 
    if mydate.hour < 10:
        formatteddate += "0"    
    formatteddate += str(mydate.hour)
    if mydate.minute < 10:
        formatteddate += "0"    
    formatteddate += str(mydate.minute)    
    if mydate.second < 10:
        formatteddate += "0"    
    formatteddate += str(mydate.second)    
    
    return formatteddate       

########################################################################
# main function

if __name__ == '__main__':

    global logger

    parser = init_parse_argument()
    args = parser.parse_args()
    log = args.log
    versionFilter = args.versionFilter
    if versionFilter == None:
        versionFilter = 'LAST'
    if versionFilter != 'LAST' and versionFilter != 'ALL':
        versionFilter = 'LAST'
    detailLevel = 'Intermediate'
    if args.detailLevel != None and (args.detailLevel == 'Simple' or args.detailLevel == 'Full'):
        detailLevel = args.detailLevel

    # setup logging
    logger = logging.getLogger(__name__)
    handler = logging.FileHandler(log, mode="w")
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    # log params
    logger.info('****************** params ******************')
    logger.info('log='+log)
    logger.info('versionFilter='+versionFilter)
    logger.info('detailLevel ='+detailLevel)
    logger.info('********************************************')

    try:
        listQualityRules = []

        # initialize connection
        connection = get_connection(logger, 'technologies.castsoftware.com', 'https')    
        #####################################################
        # retrieve platform versions & quality rules
        platform_versions = get_platform_versions(logger, connection)
        iversion = 0
        for version in platform_versions:
            iversion += 1 
            # breaking if we keep only the LAST
            if iversion > 1 and versionFilter == 'LAST':
                break

            msg = 'Platform version ' + version['name'] + ': processing'
            logger.info(msg)
            print(msg)
            json_qrs = get_platform_version_qualityrules(logger, connection, version['name'])
            if json_qrs != None:
                for json_qr in json_qrs: 
                    qci = None
                    qci = parse_jsonqr(logger, connection, json_qr, iversion, detailLevel)
                    qci.parentType = 'Platform'
                    qci.parentName = 'Platform'
                    qci.parentVersion = version['name']
                    listQualityRules.append(qci)
                    #log_qci(logger,qci)
        
        #####################################################    
        # retrieve extensions versions & quality rules
        extensions = get_extensions(logger, connection)
        for extension in extensions:
            versions = get_extensions_versions(logger, connection, extension['name'])
            iversion = 0
            if versions == None: 
                continue
            for version in versions:
                iversion+=1
                # breaking if we keep only the LAST                
                if iversion > 1 and versionFilter == 'LAST':
                    break
                
                msg = 'Extension ' + extension['name'] + ' ' + version['name'] + ': processing'
                logger.info(msg)
                print(msg)                
                json_qrs = get_extensions_versions_qualityrules(logger, connection, extension['name'], version['name'])
                if json_qrs != None:
                    for json_qr in json_qrs: 
                        qci = parse_jsonqr(logger, connection, json_qr, iversion, detailLevel)
                        qci.parentType = 'Product extension'
                        qci.parentName = extension['name']
                        qci.parentVersion = version['name']
                        listQualityRules.append(qci)
                        #log_qci(logger,qci)
        
        currentdate = datetime.datetime.today()
        iCounter = 0
        mycsvdatas = []
        for data in listQualityRules:
            iCounter+=1
            mycsvdatas.append(qci_to_dictitem(logger, data))
        
        # csv file path
        csvfilepath = 'CAST_QualityRules_' + versionFilter + '_' + detailLevel + "_" + get_formatted_dateandtime(currentdate) + '.csv'
        with open(csvfilepath, mode='w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=';')
            # write in csv file
            csv_writer.writerow(['Type','Parent','Version','Last version','Quality rule id','Quality rule name','Critical','Technologies','Href','Standards','Business criteria contribution','Technical criteria contribution','Rest Href'])
            csv_writer.writerows(mycsvdatas)
        msg = 'Completed with success. File ' + csvfilepath + ' generated with ' + str(iCounter) + ' rows'        
        logger.info(msg)
        print(msg)           
           
    except: # catch *all* exceptions
        tb = traceback.format_exc()
        #e = sys.exc_info()[0]
        logging.error('  Error during the processing %s' % tb)


########################################################################

