@echo off
REM NetworkSpy Launch Script for Windows
REM This script helps launch the NetworkSpy application

echo 🕵️  Starting NetworkSpy - Network Intelligence Dashboard
echo ==================================================

REM Check if Java is installed
java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Java is not installed or not in PATH
    echo Please install Java 17 or higher
    pause
    exit /b 1
)

REM Check if Maven is installed
mvn -version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Maven is not installed or not in PATH
    echo Please install Maven to build the project
    pause
    exit /b 1
)

REM Create logs directory
if not exist "logs" mkdir logs

REM Build the project
echo 🔨 Building project...
mvn clean compile -q

if %errorlevel% neq 0 (
    echo ❌ Build failed. Please check the error messages above.
    pause
    exit /b 1
)

echo ✅ Build successful

REM Check for elevated privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️  Warning: Running without elevated privileges
    echo    Some network monitoring features may not work properly
    echo    Consider running as Administrator
    echo.
)

echo 🚀 Launching NetworkSpy...
echo    - The application will open in a new window
echo    - Click 'START SCAN' to begin monitoring
echo    - Close the application window to stop
echo.

REM Run the application
mvn javafx:run

echo 👋 NetworkSpy has been terminated
pause
