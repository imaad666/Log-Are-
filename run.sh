#!/bin/bash

# NetworkSpy Launch Script
# This script helps launch the NetworkSpy application with proper permissions

echo "🕵️  Starting NetworkSpy - Network Intelligence Dashboard"
echo "=================================================="

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "❌ Java is not installed or not in PATH"
    echo "Please install Java 17 or higher"
    exit 1
fi

# Check Java version
java_version=$(java -version 2>&1 | head -1 | cut -d'"' -f2 | sed '/^1\./s///' | cut -d'.' -f1)
if [ "$java_version" -lt 17 ]; then
    echo "⚠️  Java version is $java_version, but Java 17+ is recommended"
fi

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "❌ Maven is not installed or not in PATH"
    echo "Please install Maven to build the project"
    exit 1
fi

# Create logs directory
mkdir -p logs

# Build the project
echo "🔨 Building project..."
mvn clean compile -q

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi

echo "✅ Build successful"

# Check for elevated privileges
if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if [ "$EUID" -ne 0 ]; then
        echo "⚠️  Warning: Running without elevated privileges"
        echo "   Some network monitoring features may not work properly"
        echo "   Consider running with: sudo ./run.sh"
        echo ""
    fi
fi

echo "🚀 Launching NetworkSpy..."
echo "   - The application will open in a new window"
echo "   - Click 'START SCAN' to begin monitoring"
echo "   - Press Ctrl+C in this terminal to stop"
echo ""

# Run the application
mvn javafx:run

echo "👋 NetworkSpy has been terminated"
