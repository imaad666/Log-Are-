package com.spynet.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a network event (connection, disconnection, traffic, etc.)
 */
public class NetworkEvent {
    
    public enum EventType {
        DEVICE_CONNECTED("🔗", "Device Connected"),
        DEVICE_DISCONNECTED("❌", "Device Disconnected"),
        HTTP_REQUEST("🌐", "HTTP Request"),
        HTTPS_REQUEST("🔒", "HTTPS Request"),
        DNS_QUERY("🔍", "DNS Query"),
        FILE_TRANSFER("📁", "File Transfer"),
        STREAMING("📺", "Media Streaming"),
        UNKNOWN("❓", "Unknown Traffic");
        
        private final String icon;
        private final String displayName;
        
        EventType(String icon, String displayName) {
            this.icon = icon;
            this.displayName = displayName;
        }
        
        public String getIcon() { return icon; }
        public String getDisplayName() { return displayName; }
    }
    
    private final LocalDateTime timestamp;
    private final EventType type;
    private final String sourceIP;
    private final String destinationIP;
    private final String deviceName;
    private final String description;
    private final int dataSize;
    
    private static final DateTimeFormatter TIMESTAMP_FORMAT = 
        DateTimeFormatter.ofPattern("HH:mm:ss.SSS");
    
    public NetworkEvent(EventType type, String sourceIP, String destinationIP, 
                       String deviceName, String description, int dataSize) {
        this.timestamp = LocalDateTime.now();
        this.type = type;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.deviceName = deviceName;
        this.description = description;
        this.dataSize = dataSize;
    }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public EventType getType() { return type; }
    public String getSourceIP() { return sourceIP; }
    public String getDestinationIP() { return destinationIP; }
    public String getDeviceName() { return deviceName; }
    public String getDescription() { return description; }
    public int getDataSize() { return dataSize; }
    
    public String getFormattedTimestamp() {
        return timestamp.format(TIMESTAMP_FORMAT);
    }
    
    public String getFormattedDataSize() {
        if (dataSize < 1024) return dataSize + " B";
        if (dataSize < 1024 * 1024) return String.format("%.1f KB", dataSize / 1024.0);
        return String.format("%.1f MB", dataSize / (1024.0 * 1024.0));
    }
    
    @Override
    public String toString() {
        return String.format("[%s] %s %s: %s -> %s (%s) - %s", 
            getFormattedTimestamp(),
            type.getIcon(),
            type.getDisplayName(),
            sourceIP,
            destinationIP,
            deviceName,
            description
        );
    }
}
