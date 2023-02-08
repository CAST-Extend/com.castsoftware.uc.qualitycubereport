@echo off

:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
REM Configure python.exe path, not required if python is on the PATH environment variable
SET PYTHONPATH=
REM SET PYTHONPATH=C:\Python\Python37\
SET PYTHONCMD=python
IF NOT "%PYTHONPATH%" == "" SET PYTHONCMD=%PYTHONPATH%\python

ECHO =================================
"%PYTHONCMD%" -V
ECHO =================================
:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

:: Output folder
SET CURRENTFOLDER=%~dp0
:: remove trailing \
SET CURRENTFOLDER=%CURRENTFOLDER:~0,-1%
SET OUTPUTFOLDER=%CURRENTFOLDER%
SET EXTENSIONINSTALLATIONFOLDER=%CURRENTFOLDER%

SET CMD="%PYTHONCMD%" "%~dp0QualityCubeReport.py" -versionFilter LAST -detailLevel Intermediate -log "%OUTPUTFOLDER%\QualityCubeReport.log"
ECHO Running %CMD%
%CMD%
SET RETURNCODE=%ERRORLEVEL%
ECHO RETURNCODE %RETURNCODE% 


PAUSE