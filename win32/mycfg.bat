@echo off
REM 
REM This is my personal configuration file. 
REM I am lazy to type all this crap again and again
REM You are welcome to customize this file for your
REM needs but do not check it into the GitHub, please.
REM
REM Mirus <mail@mirus.cz>
REM 
REM ussage : mycfg [debug]

SET ISDEBUG=no
if %1A==A set ISDEBUG=no
if %1A==debugA set ISDEBUG=yes

SET PREFIX=C:\build_VC12\Win32
if %PLATFORM%A== x64A goto DoWin64
goto doit
:DoWin64 
SET PREFIX=C:\build_VC12\Win64

:doit
SET LIBEET_INCLUDE=%PREFIX%\include;%PREFIX%\include\libxml2;%MSSDK_INCLUDE%
SET LIBEET_LIB=%PREFIX%\lib;%MSSDK_LIB%
SET LIBEET_OPTIONS=static=yes debug=%ISDEBUG% unicode=yes

del /F Makefile configure.txt version32.rc
cscript configure.js prefix=%PREFIX% %LIBEET_OPTIONS% include=%LIBEET_INCLUDE% lib=%LIBEET_LIB% sodir=%PREFIX%\bin
