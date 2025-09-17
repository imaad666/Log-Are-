package com.spynet.ui;

import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.spynet.model.NetworkDevice;
import com.spynet.model.NetworkEvent;
import com.spynet.service.NetworkMonitorService;

import javafx.application.Platform;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ListCell;
import javafx.scene.control.ListView;
import javafx.scene.control.SplitPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.stage.Stage;

/**
 * Main spy-themed UI window for the network monitoring application
 */
public class SpyMainWindow {
    
    private static final Logger logger = LoggerFactory.getLogger(SpyMainWindow.class);
    
    private Stage primaryStage;
    private NetworkMonitorService networkService;
    private ListView<NetworkEvent> eventListView;
    private ListView<NetworkDevice> deviceListView;
    private ObservableList<NetworkEvent> eventList;
    private ObservableList<NetworkDevice> deviceList;
    private Label statusLabel;
    private Label statsLabel;
    private AtomicInteger totalEvents = new AtomicInteger(0);
    private AtomicInteger activeDevices = new AtomicInteger(0);
    
    // Spy theme colors
    private static final String BACKGROUND_COLOR = "#0a0a0a";
    private static final String PANEL_COLOR = "#1a1a1a";
    private static final String ACCENT_COLOR = "#00ff00";
    private static final String TEXT_COLOR = "#c0c0c0";
    private static final String HIGHLIGHT_COLOR = "#ff4444";
    
    public void start(Stage primaryStage) {
        this.primaryStage = primaryStage;
        
        // Initialize data
        eventList = FXCollections.observableArrayList();
        deviceList = FXCollections.observableArrayList();
        
        // Setup UI
        setupUI();
        
        // Initialize network service
        networkService = new NetworkMonitorService();
        networkService.setEventListener(this::onNetworkEvent);
        networkService.setDeviceListener(this::onDeviceUpdate);
        
        // Start monitoring
        networkService.startMonitoring();
        
        primaryStage.show();
    }
    
    private void setupUI() {
        primaryStage.setTitle("🕵️ NetworkSpy - Network Intelligence Dashboard");
        primaryStage.setWidth(1400);
        primaryStage.setHeight(900);
        
        // Main container
        BorderPane root = new BorderPane();
        root.setStyle("-fx-background-color: " + BACKGROUND_COLOR + ";");
        
        // Header
        root.setTop(createHeader());
        
        // Center content
        root.setCenter(createMainContent());
        
        // Bottom status bar
        root.setBottom(createStatusBar());
        
        Scene scene = new Scene(root);
        scene.getStylesheets().add(getClass().getResource("/spy-theme.css") != null ? 
            getClass().getResource("/spy-theme.css").toExternalForm() : "");
        
        primaryStage.setScene(scene);
    }
    
    private VBox createHeader() {
        VBox header = new VBox(10);
        header.setPadding(new Insets(15));
        header.setStyle("-fx-background-color: " + PANEL_COLOR + "; -fx-border-color: " + ACCENT_COLOR + "; -fx-border-width: 0 0 2 0;");
        
        // Title
        Label titleLabel = new Label("🕵️ NETWORK SURVEILLANCE SYSTEM");
        titleLabel.setFont(Font.font("Courier New", FontWeight.BOLD, 24));
        titleLabel.setTextFill(Color.web(ACCENT_COLOR));
        
        // Subtitle
        Label subtitleLabel = new Label("CLASSIFIED - REAL-TIME NETWORK INTELLIGENCE");
        subtitleLabel.setFont(Font.font("Courier New", FontWeight.NORMAL, 12));
        subtitleLabel.setTextFill(Color.web(TEXT_COLOR));
        
        // Control buttons
        HBox controls = createControlButtons();
        
        header.getChildren().addAll(titleLabel, subtitleLabel, controls);
        header.setAlignment(Pos.CENTER_LEFT);
        
        return header;
    }
    
    private HBox createControlButtons() {
        HBox controls = new HBox(10);
        
        Button startBtn = createSpyButton("🚀 START SCAN", ACCENT_COLOR);
        Button stopBtn = createSpyButton("⏹️ STOP", HIGHLIGHT_COLOR);
        Button clearBtn = createSpyButton("🗑️ CLEAR LOGS", TEXT_COLOR);
        Button exportBtn = createSpyButton("💾 EXPORT", TEXT_COLOR);
        
        startBtn.setOnAction(e -> networkService.startMonitoring());
        stopBtn.setOnAction(e -> networkService.stopMonitoring());
        clearBtn.setOnAction(e -> clearLogs());
        exportBtn.setOnAction(e -> exportLogs());
        
        controls.getChildren().addAll(startBtn, stopBtn, clearBtn, exportBtn);
        return controls;
    }
    
    private Button createSpyButton(String text, String color) {
        Button btn = new Button(text);
        btn.setFont(Font.font("Courier New", FontWeight.BOLD, 10));
        btn.setStyle(String.format(
            "-fx-background-color: transparent; " +
            "-fx-border-color: %s; " +
            "-fx-border-width: 1; " +
            "-fx-text-fill: %s; " +
            "-fx-padding: 8 15 8 15;",
            color, color
        ));
        
        btn.setOnMouseEntered(e -> btn.setStyle(btn.getStyle() + "-fx-background-color: " + color + "33;"));
        btn.setOnMouseExited(e -> btn.setStyle(btn.getStyle().replace("-fx-background-color: " + color + "33;", "")));
        
        return btn;
    }
    
    private SplitPane createMainContent() {
        SplitPane splitPane = new SplitPane();
        splitPane.setStyle("-fx-background-color: " + BACKGROUND_COLOR + ";");
        
        // Left panel - Event log
        VBox eventPanel = createEventPanel();
        
        // Right panel - Device list
        VBox devicePanel = createDevicePanel();
        
        splitPane.getItems().addAll(eventPanel, devicePanel);
        splitPane.setDividerPositions(0.7);
        
        return splitPane;
    }
    
    private VBox createEventPanel() {
        VBox panel = new VBox(10);
        panel.setPadding(new Insets(15));
        panel.setStyle("-fx-background-color: " + PANEL_COLOR + "; -fx-border-color: " + ACCENT_COLOR + "; -fx-border-width: 1;");
        
        Label title = new Label("📊 REAL-TIME NETWORK EVENTS");
        title.setFont(Font.font("Courier New", FontWeight.BOLD, 14));
        title.setTextFill(Color.web(ACCENT_COLOR));
        
        eventListView = new ListView<>(eventList);
        eventListView.setStyle(
            "-fx-background-color: " + BACKGROUND_COLOR + "; " +
            "-fx-border-color: " + TEXT_COLOR + "; " +
            "-fx-border-width: 1;"
        );
        
        eventListView.setCellFactory(listView -> new EventListCell());
        
        panel.getChildren().addAll(title, eventListView);
        VBox.setVgrow(eventListView, Priority.ALWAYS);
        
        return panel;
    }
    
    private VBox createDevicePanel() {
        VBox panel = new VBox(10);
        panel.setPadding(new Insets(15));
        panel.setStyle("-fx-background-color: " + PANEL_COLOR + "; -fx-border-color: " + ACCENT_COLOR + "; -fx-border-width: 1;");
        
        Label title = new Label("📱 DETECTED DEVICES");
        title.setFont(Font.font("Courier New", FontWeight.BOLD, 14));
        title.setTextFill(Color.web(ACCENT_COLOR));
        
        deviceListView = new ListView<>(deviceList);
        deviceListView.setStyle(
            "-fx-background-color: " + BACKGROUND_COLOR + "; " +
            "-fx-border-color: " + TEXT_COLOR + "; " +
            "-fx-border-width: 1;"
        );
        
        deviceListView.setCellFactory(listView -> new DeviceListCell());
        
        panel.getChildren().addAll(title, deviceListView);
        VBox.setVgrow(deviceListView, Priority.ALWAYS);
        
        return panel;
    }
    
    private HBox createStatusBar() {
        HBox statusBar = new HBox(20);
        statusBar.setPadding(new Insets(10));
        statusBar.setStyle("-fx-background-color: " + PANEL_COLOR + "; -fx-border-color: " + ACCENT_COLOR + "; -fx-border-width: 2 0 0 0;");
        
        statusLabel = new Label("🔴 MONITORING INACTIVE");
        statusLabel.setFont(Font.font("Courier New", FontWeight.BOLD, 12));
        statusLabel.setTextFill(Color.web(HIGHLIGHT_COLOR));
        
        statsLabel = new Label("Events: 0 | Active Devices: 0 | Data Captured: 0 MB");
        statsLabel.setFont(Font.font("Courier New", FontWeight.NORMAL, 10));
        statsLabel.setTextFill(Color.web(TEXT_COLOR));
        
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        
        Label timeLabel = new Label("SYSTEM TIME: " + java.time.LocalDateTime.now().toString());
        timeLabel.setFont(Font.font("Courier New", FontWeight.NORMAL, 10));
        timeLabel.setTextFill(Color.web(TEXT_COLOR));
        
        statusBar.getChildren().addAll(statusLabel, statsLabel, spacer, timeLabel);
        
        return statusBar;
    }
    
    private void onNetworkEvent(NetworkEvent event) {
        Platform.runLater(() -> {
            eventList.add(0, event); // Add to top
            if (eventList.size() > 1000) { // Limit to prevent memory issues
                eventList.remove(eventList.size() - 1);
            }
            
            totalEvents.incrementAndGet();
            updateStats();
            
            // Auto-scroll to top
            if (!eventListView.getItems().isEmpty()) {
                eventListView.scrollTo(0);
            }
        });
    }
    
    private void onDeviceUpdate(NetworkDevice device) {
        Platform.runLater(() -> {
            int existingIndex = deviceList.indexOf(device);
            if (existingIndex >= 0) {
                deviceList.set(existingIndex, device);
            } else {
                deviceList.add(device);
                activeDevices.incrementAndGet();
            }
            updateStats();
        });
    }
    
    private void updateStats() {
        long totalData = deviceList.stream().mapToLong(NetworkDevice::getTotalDataTransferred).sum();
        String dataFormatted = formatBytes(totalData);
        
        statsLabel.setText(String.format("Events: %d | Active Devices: %d | Data Captured: %s", 
            totalEvents.get(), activeDevices.get(), dataFormatted));
        
        statusLabel.setText("🟢 MONITORING ACTIVE");
        statusLabel.setTextFill(Color.web(ACCENT_COLOR));
    }
    
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024.0));
        return String.format("%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
    
    private void clearLogs() {
        eventList.clear();
        totalEvents.set(0);
        updateStats();
    }
    
    private void exportLogs() {
        // TODO: Implement log export functionality
        logger.info("Export logs requested");
    }
    
    
    // Custom list cells for styling
    private class EventListCell extends ListCell<NetworkEvent> {
        @Override
        protected void updateItem(NetworkEvent event, boolean empty) {
            super.updateItem(event, empty);
            
            if (empty || event == null) {
                setText(null);
                setStyle("");
            } else {
                setText(event.toString());
                setFont(Font.font("Courier New", 10));
                setTextFill(Color.web(TEXT_COLOR));
                setStyle("-fx-background-color: transparent;");
                
                // Color code by event type
                switch (event.getType()) {
                    case DEVICE_CONNECTED -> setTextFill(Color.web(ACCENT_COLOR));
                    case DEVICE_DISCONNECTED -> setTextFill(Color.web(HIGHLIGHT_COLOR));
                    case HTTPS_REQUEST -> setTextFill(Color.web("#ffaa00"));
                    case DNS_QUERY -> setTextFill(Color.web("#00aaff"));
                    default -> setTextFill(Color.web(TEXT_COLOR));
                }
            }
        }
    }
    
    private class DeviceListCell extends ListCell<NetworkDevice> {
        @Override
        protected void updateItem(NetworkDevice device, boolean empty) {
            super.updateItem(device, empty);
            
            if (empty || device == null) {
                setText(null);
                setStyle("");
            } else {
                setText(device.toString());
                setFont(Font.font("Courier New", 10));
                setTextFill(device.isConnected() ? Color.web(ACCENT_COLOR) : Color.web(TEXT_COLOR));
                setStyle("-fx-background-color: transparent;");
            }
        }
    }
}
