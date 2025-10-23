@echo off
REM Compilation script for RegistryTransactionLogParser
REM WinToolsSuite Serie 3 - Forensics Tool #20

echo ========================================
echo Building RegistryTransactionLogParser
echo ========================================

cl.exe /nologo /W4 /EHsc /O2 /DUNICODE /D_UNICODE ^
    /Fe:RegistryTransactionLogParser.exe ^
    RegistryTransactionLogParser.cpp ^
    /link ^
    comctl32.lib shlwapi.lib advapi32.lib user32.lib gdi32.lib shell32.lib

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ========================================
    echo Build successful!
    echo Executable: RegistryTransactionLogParser.exe
    echo ========================================
    if exist RegistryTransactionLogParser.obj del RegistryTransactionLogParser.obj
) else (
    echo.
    echo ========================================
    echo Build FAILED!
    echo ========================================
    exit /b 1
)
