package com.spynet.model;

import java.time.LocalDateTime;

/**
 * Represents a device on the network
 */
public class NetworkDevice {
    
    public enum DeviceType {
        PHONE("📱", "Mobile Phone"),
        LAPTOP("💻", "Laptop"),
        DESKTOP("🖥️", "Desktop"),
        TABLET("📱", "Tablet"),
        ROUTER("📡", "Router"),
        IOT("🏠", "IoT Device"),
        GAME_CONSOLE("🎮", "Game Console"),
        TV("📺", "Smart TV"),
        UNKNOWN("❓", "Unknown Device");
        
        private final String icon;
        private final String displayName;
        
        DeviceType(String icon, String displayName) {
            this.icon = icon;
            this.displayName = displayName;
        }
        
        public String getIcon() { return icon; }
        public String getDisplayName() { return displayName; }
    }
    
    private final String ipAddress;
    private final String macAddress;
    private String hostname;
    private DeviceType deviceType;
    private boolean isConnected;
    private LocalDateTime lastSeen;
    private final LocalDateTime firstSeen;
    private long totalDataTransferred;
    private int connectionCount;
    
    public NetworkDevice(String ipAddress, String macAddress) {
        this.ipAddress = ipAddress;
        this.macAddress = macAddress;
        this.hostname = "Unknown";
        this.deviceType = DeviceType.UNKNOWN;
        this.isConnected = true;
        this.firstSeen = LocalDateTime.now();
        this.lastSeen = LocalDateTime.now();
        this.totalDataTransferred = 0;
        this.connectionCount = 0;
    }
    
    // Getters
    public String getIpAddress() { return ipAddress; }
    public String getMacAddress() { return macAddress; }
    public String getHostname() { return hostname; }
    public DeviceType getDeviceType() { return deviceType; }
    public boolean isConnected() { return isConnected; }
    public LocalDateTime getLastSeen() { return lastSeen; }
    public LocalDateTime getFirstSeen() { return firstSeen; }
    public long getTotalDataTransferred() { return totalDataTransferred; }
    public int getConnectionCount() { return connectionCount; }
    
    // Setters
    public void setHostname(String hostname) { this.hostname = hostname; }
    public void setDeviceType(DeviceType deviceType) { this.deviceType = deviceType; }
    public void setConnected(boolean connected) { this.isConnected = connected; }
    public void updateLastSeen() { this.lastSeen = LocalDateTime.now(); }
    public void addDataTransferred(long bytes) { this.totalDataTransferred += bytes; }
    public void incrementConnectionCount() { this.connectionCount++; }
    
    public String getFormattedDataTransferred() {
        if (totalDataTransferred < 1024) return totalDataTransferred + " B";
        if (totalDataTransferred < 1024 * 1024) return String.format("%.1f KB", totalDataTransferred / 1024.0);
        if (totalDataTransferred < 1024 * 1024 * 1024) return String.format("%.1f MB", totalDataTransferred / (1024.0 * 1024.0));
        return String.format("%.1f GB", totalDataTransferred / (1024.0 * 1024.0 * 1024.0));
    }
    
    @Override
    public String toString() {
        return String.format("%s %s (%s) - %s [%s]", 
            deviceType.getIcon(),
            hostname,
            ipAddress,
            isConnected ? "ONLINE" : "OFFLINE",
            getFormattedDataTransferred()
        );
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        NetworkDevice device = (NetworkDevice) obj;
        return ipAddress.equals(device.ipAddress) || macAddress.equals(device.macAddress);
    }
    
    @Override
    public int hashCode() {
        return ipAddress.hashCode() + macAddress.hashCode();
    }
}
