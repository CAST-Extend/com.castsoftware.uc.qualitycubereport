@echo off

SET AIP_DEFAULT_BIN_DIR=C:\Program Files\CAST\8.3
IF "%PYTHONPATH%"=="" SET PYTHONPATH=%AIP_DEFAULT_BIN_DIR%\ThirdParty\Python34

:: Output folder
SET OUTPUTFOLDER=C:\Users\mmr\workspace\com.castsoftware.uc.qualitycubereport.local_2

SET CMD="%PYTHONPATH%\python" "%~dp0QualityCubeReport.py" -versionFilter ALL -detailLevel Intermediate -log "%OUTPUTFOLDER%\QualityCubeReport.log"
ECHO Running %CMD%
%CMD%
SET RETURNCODE=%ERRORLEVEL%
ECHO RETURNCODE %RETURNCODE% 


PAUSE