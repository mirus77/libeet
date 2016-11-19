@echo off
rem Run in _buildx86.bat or _buildx64.bat environment

call mycfg.bat
if exist Makefile nmake clean
if exist Makefile nmake bindist
