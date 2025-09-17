package com.spynet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.spynet.ui.SpyMainWindow;

import javafx.application.Application;
import javafx.stage.Stage;

/**
 * Main application class for NetworkSpy - A spy-themed network monitoring tool
 */
public class NetworkSpyApp extends Application {
    
    private static final Logger logger = LoggerFactory.getLogger(NetworkSpyApp.class);
    
    @Override
    public void start(Stage primaryStage) {
        try {
            logger.info("Starting NetworkSpy application...");
            
            SpyMainWindow mainWindow = new SpyMainWindow();
            mainWindow.start(primaryStage);
            
        } catch (Exception e) {
            logger.error("Failed to start NetworkSpy application", e);
            System.exit(1);
        }
    }
    
    public static void main(String[] args) {
        logger.info("Initializing NetworkSpy...");
        launch(args);
    }
}
