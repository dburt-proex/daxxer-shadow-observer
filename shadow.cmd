@echo off
python -B "%~dp0scripts\shadow.py" %*
exit /b %errorlevel%
