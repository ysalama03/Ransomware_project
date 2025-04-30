@echo off
del /Q "%~dp0\*.pyc"
rmdir /S /Q "%~dp0\__pycache__"