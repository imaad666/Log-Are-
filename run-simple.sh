#!/bin/bash

# Simple NetworkSpy Launch Script
# This script runs the application with direct Java execution

echo "🕵️  Starting NetworkSpy - Simple Launch Mode"
echo "============================================="

# Build first
echo "🔨 Building project..."
mvn clean compile -q

if [ $? -ne 0 ]; then
    echo "❌ Build failed. Please check the error messages above."
    exit 1
fi

echo "✅ Build successful"

# Create logs directory
mkdir -p logs

echo "🚀 Launching NetworkSpy with direct Java execution..."

# Run with direct Java command and macOS-specific flags
java --enable-native-access=ALL-UNNAMED \
     --enable-native-access=javafx.graphics \
     --add-modules javafx.controls,javafx.fxml \
     --module-path ~/.m2/repository/org/openjfx/javafx-controls/21.0.1:~/.m2/repository/org/openjfx/javafx-base/21.0.1:~/.m2/repository/org/openjfx/javafx-graphics/21.0.1:~/.m2/repository/org/openjfx/javafx-fxml/21.0.1 \
     -cp "target/classes:$(mvn dependency:build-classpath -q -Dmdep.outputFile=/dev/stdout)" \
     com.spynet.NetworkSpyApp

echo "👋 NetworkSpy has been terminated"
