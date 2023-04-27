
'''
Created on 13 avr. 2020

@author: MMR
'''

####################################################################################

class StringUtils:
    @staticmethod 
    def NonetoEmptyString(obj):
        if obj == None or obj == 'None':
            return ''
        return obj

####################################################################################

# Logging utils
class LogUtils:

    @staticmethod
    def loginfo(logger, msg, tosysout = False):
        logger.info(msg)
        if tosysout:
            print(msg)

    @staticmethod
    def logdebug(logger, msg, tosysout = False):
        logger.debug(msg)
        if tosysout:
            print(msg)

    @staticmethod
    def logwarning(logger, msg, tosysout = False):
        logger.warning(msg)
        if tosysout:
            print("#### " + msg)

    @staticmethod
    def logerror(logger, msg, tosysout = False):
        logger.error(msg)
        if tosysout:
            print("#### " + msg)