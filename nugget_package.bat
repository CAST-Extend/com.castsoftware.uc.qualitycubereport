@echo off
set version=%1
set nuggetexe=C:\Program Files\Nuget\nuget.exe
set EnableNugetPackageRestore=true
"%nuggetexe%" pack dist\plugin.nuspec -ExcludeEmptyDirectories -version %version% 