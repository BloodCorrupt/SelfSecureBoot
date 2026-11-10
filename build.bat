@echo off
REM ========================================================
REM  SelfSecureBoot (EFI Signer) - Cross-Platform Build Script
REM ========================================================

echo [1/3] Cleaning previous build...
if exist distribute rmdir /s /q distribute

echo [2/3] Publishing SelfSecureBoot (Windows x64 single-file)...
dotnet publish SelfSecureBoot.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o distribute\win-x64
if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED: Windows x64
    if not defined CI pause
    exit /b 1
)

echo [3/3] Publishing SelfSecureBoot (Linux x64 single-file)...
dotnet publish SelfSecureBoot.csproj -c Release -r linux-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o distribute\linux-x64
if %ERRORLEVEL% neq 0 (
    echo BUILD FAILED: Linux x64
    if not defined CI pause
    exit /b 1
)

echo.
echo ========================================================
echo Build complete!
echo Output artifacts:
echo   distribute\win-x64\SelfSecureBoot.exe
echo   distribute\linux-x64\SelfSecureBoot
echo ========================================================
if not defined CI pause

