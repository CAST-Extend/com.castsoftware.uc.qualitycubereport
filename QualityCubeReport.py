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
import os
import copy

########################################################################
# Class containing all the attributed to be sent to the CSV file

class QualityCubeItem:
 
    # Class attributes
    metricId = None
    metricName = None
    critical = False
    status = ''
    
    # type possible values = quality-rules / technical-criteria / quality-distributions
    type = None
    
    # parentType possible values = platform / extension
    parentType = ''
    parentName = ''
    parentTitle = ''
    parentVersion = ''
    lastVersion = None
    maxWeight = ''
    maxWeightRecomputed = -1 
    
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
    threshold1 = 0
    threshold2 = 0
    threshold3 = 0
    threshold4 = 0
    
    # rule documentation
    alternativeName = ''
    associatedValueName = ''
    description = ''
    output = ''
    rationale = ''       
    remediation = ''
    total = ''      


    # CRC on quality rules / metamodel changes 
    rulesCRC = ''
    metaModelCRC = ''

    #####################################################################""
    
    
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
    #msg = "Type;Parent name;Parent title;Version;Last version;Quality rule id;Quality rule name;Critical;Technologies;Href;Standards;Business criteria contribution;Technical criteria contribution;Rest Href"
    
    #Href
    msg = qci.parentType + ";" + qci.parentName + ";"+ qci.parentTitle + ";" + qci.parentVersion + ";" + str(qci.lastVersion) + ";" + str(qci.metricId) + ";" + qci.metricName + ";" + str(qci.critical) + ";" + ";" + str(qci.maxWeight) + ";"

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
    
def qci_to_dictitem(logger, qci, detailLevel):

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
        print(str(qci.metricId) + ";" + qci.metricName + ";" +  qs)   

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

    # List of parameters
    listparam = ''
    for param in qci.listParameters:
        listparam += param + '/'
    if listparam != '': listparam = listparam[:-1]

    if detailLevel == 'Full': 
        return [qci.parentType, qci.parentName,  qci.parentTitle,  qci.parentVersion, str(qci.lastVersion), str(qci.rulesCRC), str(qci.metaModelCRC), str(qci.metricId), qci.metricName,  str(qci.critical), qci.maxWeight, qci.status, listtec, href, listqs, listbc, listtc, str(qci.threshold1), str(qci.threshold2), str(qci.threshold3),str(qci.threshold4),listparam,qci.get_full_restHref(),qci.alternativeName,        qci.description , qci.rationale,     qci.remediation,qci.associatedValueName,qci.output,qci.total]
    elif detailLevel == 'Intermediate':        
        return [qci.parentType, qci.parentName,  qci.parentTitle,  qci.parentVersion, str(qci.lastVersion), str(qci.metricId), qci.metricName,  str(qci.critical), qci.maxWeight, qci.status, listtec, href, listqs, listbc, listtc, qci.get_full_restHref()]
    elif detailLevel == 'Simple':
        return [qci.parentType, qci.parentName,  qci.parentTitle,  qci.parentVersion, str(qci.lastVersion), str(qci.metricId), qci.metricName,  str(qci.critical), qci.status, listtec, href]

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
def get_extension_details(logger, connection, extension_id):
    request = "/AIP/extensions/" + extension_id
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
# dirty workaround to remove the unicode characters before sending them to the CSV file
# and avoid the below error
#File "C:\Users\mmr\workspace\com.castsoftware.uc.qualitycubereport.local_2\QualityCubeReport.py", line 452, in <module>
#csv_writer.writerow(row)
#File "C:\Program Files\CAST\8.1\ThirdParty\Python34\lib\encodings\cp1252.py", line 19, in encode
#return codecs.charmap_encode(input,self.errors,encoding_table)[0]
#UnicodeEncodeError: 'charmap' codec can't encode character '\x85' in position 105: character maps to <undefined>    

def remove_unicode_characters(astr):
    mystr = astr
    mystr = mystr.replace('\x85', '')
    mystr = mystr.replace('\x95', '')
    mystr = mystr.replace('\ufb01', '')
    mystr = mystr.replace('\ufb02', '')
    mystr = mystr.replace('\x92', '')
    mystr = mystr.replace('\x97','')
    mystr = mystr.replace('\x93','')
    mystr = mystr.replace('\x94','')
    mystr = mystr.replace('\u200b','')
    mystr = mystr.replace('\x96','')
    return mystr

########################################################################
# parse the quality rule json

def parse_load_jsonqr(logger, connection, json_qr, index, detailLevel):
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

    # temporary dirty workaround to avoid the below error
    # QualityCubeReport.py", line 452, in <module>
    # UnicodeEncodeError: 'charmap' codec can't encode character '\x85' in position 105: character maps to <undefined>    
    if x.metricId == 1001136:
        x.metricName = remove_unicode_characters(json_qr['name'])
        #x.metricName = 'Avoid Main Procedures having "SELECT * FROM ..." clause (PL1)'
    
    x.critical = json_qr['critical']
    x.status = json_qr['status']

    x.type = 'quality-rules'
    
    # Last version for the platform or extension
    if index == 1:
        x.lastVersion = True
    
    # list of technologies
    for tech in json_qr['technologyNames']:
        x.add_technology(tech)
    
    # we look at the quality rules details only if we detail Level is not Simple but Intermediate or Full, because it's very time consuming
    # we do that only for the last version, because we don't have history for those data, it's available only in the last version 
    if (detailLevel == 'Intermediate' or detailLevel == 'Full') and x.lastVersion and x.restHref != None and x.restHref != '':
        json_qrdetail = execute_request(logger, connection,  x.restHref)
        try:
            x.maxWeight = str(json_qrdetail['maxWeight'])
        except KeyError:
            x.maxWeight = ''
        
        for bc in json_qrdetail['businessCriteria']:
            x.add_businesscriterion(bc['name'])
        for tc in json_qrdetail['technicalCriteria']:
            x.add_technicalcriterion(tc['name']+'#'+str(tc['critical'])+'#'+str(tc['weight']))
            if tc['weight'] > x.maxWeightRecomputed: 
                x.maxWeightRecomputed = tc['weight']
                # Fix in the rest API data, maxWeight is not always filled where it should
                if x.maxWeight == '': x.maxWeight = x.maxWeightRecomputed
            
        for qs in json_qrdetail['qualityStandards']:
            x.add_qualitystandard(qs['standard'] + ":" + qs['id'])       
    
        if detailLevel == 'Full':
            # parameters
            for param in json_qrdetail['parameters']:
                x.add_parameter(param['name'])          
    
            # thresholds
            ithres = 0
            for trsh in json_qrdetail['thresholds']:
                ithres += 1
                if ithres == 1:
                    x.threshold1 = trsh
                elif ithres == 2:
                    x.threshold2 = trsh
                elif ithres == 3:
                    x.threshold3 = trsh
                elif ithres == 4:
                    x.threshold4 = trsh       
    
            # rule documentation
            try:
                x.alternativeName = json_qrdetail['alternativeName']
            except KeyError:
                x.alternativeName = ''
            try:
                x.associatedValueName = json_qrdetail['associatedValueName']
            except KeyError:
                x.associatedValueName = ''
            try:
                x.description = remove_unicode_characters(json_qrdetail['description'])
            except UnicodeEncodeError:
                x.description = 'UnicodeEncodeError'
            except KeyError:
                x.description = ''
            try:
                x.output = json_qrdetail['output']
            except KeyError:
                x.output = ''
            try:            
                x.rationale = remove_unicode_characters(json_qrdetail['rationale'])
            except UnicodeEncodeError:
                x.rationale = 'UnicodeEncodeError'
            except KeyError:
                x.rationale = ''
            try:            
                x.remediation = remove_unicode_characters(json_qrdetail['remediation'])
            except UnicodeEncodeError:
                x.remediation = 'UnicodeEncodeError'
            except KeyError:
                x.remediation = ''
            try:            
                x.total = json_qrdetail['total']
            except KeyError:
                x.total = ''
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

    loadNmax = False

    parser = init_parse_argument()
    args = parser.parse_args()
    log = args.log
    versionFilter = args.versionFilter
    if versionFilter == None:
        versionFilter = 'LAST'
    if versionFilter != 'LAST' and versionFilter != 'ALL':
        versionFilter = 'LAST'
    detailLevel = 'Intermediate'
    if args.detailLevel != None and (args.detailLevel == 'Simple' or args.detailLevel == 'Intermediate' or args.detailLevel == 'Full'):
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
        listQualityRulesForComponentVersion = []
        dictQualityRules = {}

        # initialize connection
        connection = get_connection(logger, 'technologies.castsoftware.com', 'https')    
        #####################################################
        # retrieve platform versions & quality rules
        platform_versions = get_platform_versions(logger, connection)
        iversion = 0
        for version in platform_versions:
            iversion += 1 
            # mise au point
            #break
            # breaking in the second iteration if we keep only the LAST version
            if iversion > 1 and versionFilter == 'LAST':
                break

            msg = 'Platform version ' + version['name'] + ': processing'
            '''logger.info(msg)
            print(msg)
            '''
            json_qrs = get_platform_version_qualityrules(logger, connection, version['name'])
            if json_qrs != None:
                icount = 0
                for json_qr in json_qrs: 
                    icount+=1
                    if loadNmax != None and loadNmax and icount > 30:
                        break 
                    qci = None
                    href = None
                    try: href = '/' + json_qr['href'] 
                    except: None
                    if href == None or dictQualityRules.get(href) == None:
                        # load the data from the rest API, the first time
                        qci = parse_load_jsonqr(logger, connection, json_qr, iversion, detailLevel)
                        # append the dict
                        dictQualityRules[qci.restHref] = qci
                    else:
                        # reuse what have been already loaded
                        qci = copy.deepcopy(dictQualityRules.get(href))
                    qci.parentType = 'Platform'
                    qci.parentName = 'Platform'
                    qci.parentTitle = 'Platform'
                    qci.parentVersion = version['name']
                    listQualityRulesForComponentVersion.append(qci)
                    #log_qci(logger,qci)
        
        #####################################################    
        # retrieve extensions versions & quality rules
        extensions = get_extensions(logger, connection)
        iext = 0
        #for extension in extensions:
        #    print(extension['name'])
        if extensions != None:
            for extension in extensions:
                iext += 1
                # pour mise au point
                #break
                #if iext > 1:
                #    break
                extensionDetails = get_extension_details(logger, connection, extension['name'])
                if extensionDetails == None:
                    msg = 'Extension '  + extension['name'] + ' not found, skipping.'
                    '''logger.warning(msg)
                    print(msg)
                    '''
                else:
                    # mise au point     
                    #if extension['name'] != 'com.castsoftware.egl':
                    #    continue 
                    hasQualityModel = extensionDetails['qualityModel']
                    hasTransactionsConfiguration = extensionDetails['transactionsConfiguration']
                    
                    versions = get_extensions_versions(logger, connection, extension['name'])
                    iversion = 0
                    if versions == None: 
                        continue
                    for version in versions:
                        iversion+=1
                        # breaking if we keep only the LAST                
                        if iversion > 1 and versionFilter == 'LAST':
                            break
                        
                        msg = 'Extension ' + extension['name'] + ' ' + version['name'] + '(QM: ' + str(hasQualityModel) + ' TR: '+ str(hasTransactionsConfiguration) +  ') : processing. '
                        if not hasQualityModel:
                            msg += '  No quality model, skipping'
                        '''logger.info(msg)
                        print(msg)
                        '''
                        if hasQualityModel:
                            json_qrs = get_extensions_versions_qualityrules(logger, connection, extension['name'], version['name'])
                            if json_qrs != None:
                                for json_qr in json_qrs: 
                                    qci = None
                                    href = None
                                    try: href = '/' + json_qr['href'] 
                                    except: None
                                    if href == None or dictQualityRules.get(href) == None:
                                        # load the data from the rest API, the first time
                                        qci = parse_load_jsonqr(logger, connection, json_qr, iversion, detailLevel)
                                        # append the dict
                                        dictQualityRules[qci.restHref] = qci
                                    else:
                                        # reuse what have been already loaded
                                        qci = copy.deepcopy(dictQualityRules.get(href))                                    
                                    qci.parentType = 'Extension'
                                    qci.parentName = extension['name']
                                    qci.parentTitle = extensionDetails['title']
                                    qci.parentVersion = version['name']
                                    qci.rulesCRC = version['rulesCRC']
                                    qci.metaModelCRC = version['metaModelCRC']
                                    listQualityRulesForComponentVersion.append(qci)
    
    
                                    #### mise au point
                                    '''
                                    currentdate = datetime.datetime.today()
                                    # csv file path
                                    mycsvdatas = []
                                    for data in listQualityRulesForComponentVersion:
                                        mycsvdatas.append(qci_to_dictitem(logger, data, detailLevel))
                                    csvfilepath = 'CAST_TempQualityRules_' + versionFilter + '_' + detailLevel + "_" + get_formatted_dateandtime(currentdate) + '.csv'
                                    with open(csvfilepath, mode='w', newline='') as csv_file:
                                        csv_writer = csv.writer(csv_file, delimiter=';')
                                        csv_writer.writerow(['Type','Parent name','Parent title','Version','Last version','Rules CRC','Metamodel CRC','Quality rule id','Quality rule name','Critical','MaxWeight','Status','Technologies','Href','Standards','Business criteria contribution','Technical criteria contribution (Name#Critical#Weight)','Threshold 1','Threshold 2','Threshold 3','Threshold 4','Parameters','Rest Href','Alternative name','Description', 'Rationale', 'Remediation','Associated value','Output','Total'])
                                        for row in mycsvdatas:
                                            logger.debug(str(row))
                                            csv_writer.writerow(row)
                                    '''
                                    #### fin mise au point
            
        currentdate = datetime.datetime.today()
        iCounter = 0
        mycsvdatas = []
        for data in listQualityRulesForComponentVersion:
            iCounter+=1
            mycsvdatas.append(qci_to_dictitem(logger, data, detailLevel))
        
        # csv file path
        csvfilepath = 'CAST_QualityRules_' + versionFilter + '_' + detailLevel + "_" + get_formatted_dateandtime(currentdate) + '.csv'
        with open(csvfilepath, mode='w', newline='') as csv_file:
            csv_writer = csv.writer(csv_file, delimiter=';')
            # write in csv file
            if detailLevel == 'Full':
                csv_writer.writerow(['Type','Parent name','Parent title','Version','Last version','Rules CRC','Metamodel CRC','Quality rule id','Quality rule name','Critical','MaxWeight','Status','Technologies','Href','Standards','Business criteria contribution','Technical criteria contribution (Name#Critical#Weight)','Threshold 1','Threshold 2','Threshold 3','Threshold 4','Parameters','Rest Href','Alternative name','Description', 'Rationale', 'Remediation','Associated value','Output','Total'])
            elif detailLevel == 'Intermediate':
                csv_writer.writerow(['Type','Parent name','Parent title','Version','Last version','Quality rule id','Quality rule name','Critical','MaxWeight','Status','Technologies','Href','Standards','Business criteria contribution','Technical criteria contribution','Rest Href'])
            elif detailLevel == 'Simple':
                csv_writer.writerow(['Type','Parent name','Parent title','Version','Last version','Quality rule id','Quality rule name','Critical','Status','Technologies','Href'])

            for row in mycsvdatas:
                # mise au point
                #logger.debug(str(row))
                csv_writer.writerow(row)
        msg = 'Completed with success. File ' + csvfilepath + ' generated with ' + str(iCounter) + ' rows'        
        logger.info(msg)
        print(msg)  
        
        
        #os.system("start "+csvfilepath)
         
           
    except: # catch *all* exceptions
        tb = traceback.format_exc()
        #e = sys.exc_info()[0]
        logging.error('  Error during the processing %s' % tb)


########################################################################

