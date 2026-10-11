@echo off
setlocal

set SCRIPT_DIR=%~dp0
set BUILDER_PY=%SCRIPT_DIR%scripts\builder.py

python "%BUILDER_PY%" %*

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed.
    pause
    exit /b %errorlevel%
)

endlocal
exit /b 0
