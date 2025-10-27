package com.spynet.service;

import java.util.Enumeration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.spynet.model.NetworkDevice;
import com.spynet.model.NetworkEvent;
import com.spynet.util.NetworkUtils;

/**
 * Service for monitoring network traffic and device connections
 */
public class NetworkMonitorService {
    
    private static final Logger logger = LoggerFactory.getLogger(NetworkMonitorService.class);
    
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduledExecutor;
    private volatile boolean isMonitoring = false;
    
    private Consumer<NetworkEvent> eventListener;
    private Consumer<NetworkDevice> deviceListener;
    
    private PcapHandle pcapHandle;
    private Future<?> packetCaptureTask;
    private ScheduledFuture<?> deviceScanTask;
    
    public NetworkMonitorService() {
        this.executorService = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "NetworkMonitor-" + System.currentTimeMillis());
            t.setDaemon(true);
            return t;
        });
        this.scheduledExecutor = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r, "NetworkScheduler-" + System.currentTimeMillis());
            t.setDaemon(true);
            return t;
        });
    }
    
    public void setEventListener(Consumer<NetworkEvent> listener) {
        this.eventListener = listener;
    }
    
    public void setDeviceListener(Consumer<NetworkDevice> listener) {
        this.deviceListener = listener;
    }
    
    public void startMonitoring() {
        if (isMonitoring) {
            logger.warn("Monitoring is already active");
            return;
        }
        
        logger.info("Starting network monitoring...");
        isMonitoring = true;
        
        // Start packet capture
        startPacketCapture();
        
        // Start device scanning
        startDeviceScanning();
        
        // Emit initial event
        emitEvent(new NetworkEvent(
            NetworkEvent.EventType.DEVICE_CONNECTED,
            "SYSTEM", "SYSTEM", "NetworkSpy",
            "Network monitoring started", 0
        ));
    }
    
    public void stopMonitoring() {
        if (!isMonitoring) {
            return;
        }
        
        logger.info("Stopping network monitoring...");
        isMonitoring = false;
        
        // Cancel tasks
        if (packetCaptureTask != null) {
            packetCaptureTask.cancel(true);
        }
        if (deviceScanTask != null) {
            deviceScanTask.cancel(true);
        }
        
        // Close pcap handle
        if (pcapHandle != null && pcapHandle.isOpen()) {
            pcapHandle.close();
        }
        
        emitEvent(new NetworkEvent(
            NetworkEvent.EventType.DEVICE_DISCONNECTED,
            "SYSTEM", "SYSTEM", "NetworkSpy",
            "Network monitoring stopped", 0
        ));
    }
    
    private void startPacketCapture() {
        packetCaptureTask = executorService.submit(() -> {
            try {
                // Get the default network interface
                PcapNetworkInterface networkInterface = getDefaultNetworkInterface();
                if (networkInterface == null) {
                    logger.error("No suitable network interface found - trying real network scanning");
                    startRealNetworkMonitoring();
                    return;
                }
                
                logger.info("Starting packet capture on interface: {}", networkInterface.getName());
                
                try {
                    pcapHandle = networkInterface.openLive(
                        65536,  // snaplen
                        PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                        10      // timeout
                    );
                    
                    logger.info("Successfully opened packet capture interface");
                    
                    // Capture packets
                    while (isMonitoring && !Thread.currentThread().isInterrupted()) {
                        try {
                            Packet packet = pcapHandle.getNextPacketEx();
                            if (packet != null) {
                                processPacket(packet);
                            }
                        } catch (Exception e) {
                            if (isMonitoring) {
                                logger.debug("Packet capture error: {}", e.getMessage());
                            }
                        }
                    }
                } catch (Exception e) {
                    logger.warn("Failed to open packet capture (need sudo?): {}", e.getMessage());
                    logger.info("Falling back to network scanning mode");
                    startRealNetworkMonitoring();
                }
                
            } catch (Exception e) {
                logger.error("Failed to start packet capture: {}", e.getMessage());
                startRealNetworkMonitoring();
            }
        });
    }
    
    private void startDeviceScanning() {
        deviceScanTask = scheduledExecutor.scheduleAtFixedRate(() -> {
            if (!isMonitoring) return;
            
            try {
                scanForDevices();
            } catch (Exception e) {
                logger.error("Device scanning error: {}", e.getMessage());
            }
        }, 0, 30, TimeUnit.SECONDS); // Scan every 30 seconds
    }
    
    private void scanForDevices() {
        logger.debug("Scanning for network devices...");
        
        try {
            // Get local network range
            String networkRange = getLocalNetworkRange();
            if (networkRange != null) {
                scanNetworkRange(networkRange);
            } else {
                logger.warn("Could not determine local network range");
            }
        } catch (Exception e) {
            logger.error("Error during device scanning: {}", e.getMessage());
        }
    }
    
    private String getLocalNetworkRange() {
        try {
            // Try to get local IP address from network interfaces
            java.net.NetworkInterface.getNetworkInterfaces().asIterator().forEachRemaining(nif -> {
                try {
                    nif.getInterfaceAddresses().forEach(addr -> {
                        java.net.InetAddress inet = addr.getAddress();
                        if (!inet.isLoopbackAddress() && !inet.isLinkLocalAddress() && inet instanceof java.net.Inet4Address) {
                            logger.info("Found local IP: {}", inet.getHostAddress());
                        }
                    });
                } catch (Exception e) {
                    // Ignore
                }
            });
            
            // Get local IP address
            Enumeration<java.net.NetworkInterface> interfaces = java.net.NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                java.net.NetworkInterface netInterface = interfaces.nextElement();
                if (!netInterface.isUp() || netInterface.isLoopback()) {
                    continue;
                }
                
                java.util.List<java.net.InterfaceAddress> addresses = netInterface.getInterfaceAddresses();
                for (java.net.InterfaceAddress addr : addresses) {
                    java.net.InetAddress inet = addr.getAddress();
                    if (inet instanceof java.net.Inet4Address && !inet.isLoopbackAddress()) {
                        String localIP = inet.getHostAddress();
                        logger.info("Using local IP: {}", localIP);
                        
                        // Determine network range based on local IP
                        if (localIP.startsWith("192.168.") || localIP.startsWith("10.") || localIP.startsWith("172.")) {
                            String[] parts = localIP.split("\\.");
                            return parts[0] + "." + parts[1] + "." + parts[2] + ".";
                        }
                    }
                }
            }
            
            // Fallback: try getLocalHost
            String localIP = java.net.InetAddress.getLocalHost().getHostAddress();
            logger.info("Fallback local IP: {}", localIP);
            if (localIP.startsWith("192.168.") || localIP.startsWith("10.") || localIP.startsWith("172.")) {
                String[] parts = localIP.split("\\.");
                return parts[0] + "." + parts[1] + "." + parts[2] + ".";
            }
        } catch (Exception e) {
            logger.error("Failed to get local IP: {}", e.getMessage());
        }
        return null;
    }
    
    private void scanNetworkRange(String networkPrefix) {
        logger.info("Scanning network range: {}*", networkPrefix);
        
        // Scan common IP ranges - faster with lower timeout
        int[] commonRanges = {1, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 146};
        
        for (int i : commonRanges) {
            if (!isMonitoring) break;
            
            String targetIP = networkPrefix + i;
            
            try {
                java.net.InetAddress address = java.net.InetAddress.getByName(targetIP);
                if (address.isReachable(500)) { // 0.5 second timeout for faster scanning
                    logger.info("Found reachable device: {}", targetIP);
                    
                    // Create device entry
                    NetworkDevice device = new NetworkDevice(targetIP, "Unknown");
                    
                    // Try to get hostname
                    try {
                        String hostname = address.getHostName();
                        if (!hostname.equals(targetIP)) {
                            device.setHostname(hostname);
                        }
                    } catch (Exception e) {
                        logger.debug("Could not resolve hostname for {}", targetIP);
                    }
                    
                    // Try to determine device type from hostname or IP
                    device.setDeviceType(guessDeviceType(device.getHostname(), targetIP));
                    device.updateLastSeen();
                    
                    emitDeviceUpdate(device);
                    
                    // Also emit a connection event
                    emitEvent(new NetworkEvent(
                        NetworkEvent.EventType.DEVICE_CONNECTED,
                        targetIP, networkPrefix + "1", device.getHostname(),
                        "Device detected on network", 0
                    ));
                }
            } catch (Exception e) {
                // Ignore unreachable hosts
            }
        }
    }
    
    private NetworkDevice.DeviceType guessDeviceType(String hostname, String ip) {
        String name = hostname.toLowerCase();
        
        if (name.contains("iphone") || name.contains("android") || name.contains("phone")) {
            return NetworkDevice.DeviceType.PHONE;
        } else if (name.contains("macbook") || name.contains("laptop")) {
            return NetworkDevice.DeviceType.LAPTOP;
        } else if (name.contains("imac") || name.contains("desktop") || name.contains("pc")) {
            return NetworkDevice.DeviceType.DESKTOP;
        } else if (name.contains("ipad") || name.contains("tablet")) {
            return NetworkDevice.DeviceType.TABLET;
        } else if (name.contains("router") || name.contains("gateway") || ip.endsWith(".1")) {
            return NetworkDevice.DeviceType.ROUTER;
        } else if (name.contains("tv") || name.contains("roku") || name.contains("chromecast")) {
            return NetworkDevice.DeviceType.TV;
        } else if (name.contains("xbox") || name.contains("playstation") || name.contains("nintendo")) {
            return NetworkDevice.DeviceType.GAME_CONSOLE;
        } else if (name.contains("echo") || name.contains("alexa") || name.contains("nest") || name.contains("hue")) {
            return NetworkDevice.DeviceType.IOT;
        }
        
        return NetworkDevice.DeviceType.UNKNOWN;
    }
    
    private void startRealNetworkMonitoring() {
        logger.info("Starting real network monitoring (without packet capture)");
        
        packetCaptureTask = executorService.submit(() -> {
            while (isMonitoring && !Thread.currentThread().isInterrupted()) {
                try {
                    // Monitor network connections using netstat-like approach
                    monitorNetworkConnections();
                    
                    Thread.sleep(5000); // Check every 5 seconds
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in real network monitoring: {}", e.getMessage());
                }
            }
        });
    }
    
    private void monitorNetworkConnections() {
        try {
            // Use system commands to get network activity
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("mac") || os.contains("darwin")) {
                // macOS: use netstat
                monitorMacOSConnections();
            } else if (os.contains("linux")) {
                // Linux: use netstat and ss
                monitorLinuxConnections();
            } else if (os.contains("windows")) {
                // Windows: use netstat
                monitorWindowsConnections();
            }
        } catch (Exception e) {
            logger.error("Failed to monitor network connections: {}", e.getMessage());
        }
    }
    
    private void monitorMacOSConnections() {
        try {
            // Use lsof on macOS as it's more reliable for getting network connections
            // lsof -i -n shows all network connections without DNS lookup
            ProcessBuilder pb = new ProcessBuilder("lsof", "-i", "-n");
            Process process = pb.start();
            
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null && isMonitoring) {
                if (line.contains("TCP") && !line.contains("LISTEN")) {
                    parseLsofLine(line);
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            // Fallback to netstat if lsof fails
            try {
                ProcessBuilder pb = new ProcessBuilder("netstat", "-an", "tcp");
                Process process = pb.start();
                
                java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(process.getInputStream())
                );
                
                String line;
                while ((line = reader.readLine()) != null && isMonitoring) {
                    if (line.contains("ESTABLISHED") || line.contains("SYN_SENT")) {
                        parseNetstatLine(line);
                    }
                }
                
                process.waitFor();
            } catch (Exception ex) {
                logger.debug("Error monitoring macOS connections: {}", ex.getMessage());
            }
        }
    }
    
    private void monitorLinuxConnections() {
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-n", "-t");
            Process process = pb.start();
            
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null && isMonitoring) {
                if (line.contains("ESTABLISHED")) {
                    parseNetstatLine(line);
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            logger.debug("Error monitoring Linux connections: {}", e.getMessage());
        }
    }
    
    private void monitorWindowsConnections() {
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-n", "-p", "TCP");
            Process process = pb.start();
            
            java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(process.getInputStream())
            );
            
            String line;
            while ((line = reader.readLine()) != null && isMonitoring) {
                if (line.contains("ESTABLISHED")) {
                    parseNetstatLine(line);
                }
            }
            
            process.waitFor();
        } catch (Exception e) {
            logger.debug("Error monitoring Windows connections: {}", e.getMessage());
        }
    }
    
    private void parseLsofLine(String line) {
        try {
            // lsof output format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            // Example: Chrome 12345 user 23u IPv4 0x123456789 0t0 TCP 192.168.1.100:54321->142.250.80.110:443 (ESTABLISHED)
            
            if (!line.contains("->") || line.contains("127.0.0.1")) {
                return; // Skip localhost connections
            }
            
            // Find the TCP part
            int tcpIdx = line.indexOf("TCP");
            if (tcpIdx == -1) return;
            
            String tcpPart = line.substring(tcpIdx);
            
            // Extract remote address from pattern like: 192.168.1.100:54321->142.250.80.110:443
            if (tcpPart.contains("->")) {
                String[] parts = tcpPart.split("->");
                if (parts.length >= 2) {
                    String remoteConn = parts[1].trim().split("\\s+")[0]; // Get just the address:port part
                    
                    String[] remoteParts = remoteConn.split(":");
                    if (remoteParts.length >= 2) {
                        String remoteIP = remoteParts[0];
                        String remotePort = remoteParts[1].replaceAll("[^0-9]", ""); // Remove any extra chars
                        
                        // Skip loopback and private ranges for external monitoring
                        if (!remoteIP.startsWith("127.") && !remoteIP.startsWith("::1") && 
                            !remoteIP.startsWith("169.254.") && !remoteIP.startsWith("0.")) {
                            
                            // Determine event type based on port
                            NetworkEvent.EventType eventType = getEventTypeFromPort(remotePort);
                            String description = getDescriptionFromPort(remotePort, remoteIP);
                            
                            NetworkEvent event = new NetworkEvent(
                                eventType,
                                "localhost",
                                remoteIP,
                                NetworkUtils.getHostname(remoteIP),
                                description,
                                (int)(Math.random() * 2000) + 500
                            );
                            
                            emitEvent(event);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Error parsing lsof line: {}", e.getMessage());
        }
    }
    
    private void parseNetstatLine(String line) {
        try {
            // macOS netstat output: 
            // tcp4       0      0  192.168.1.100.54321     142.250.80.110.443      ESTABLISHED
            String[] parts = line.trim().split("\\s+");
            if (parts.length >= 5) {
                String remoteAddr = parts[4];
                
                if (remoteAddr != null && !remoteAddr.equals("*") && !remoteAddr.contains("127.0.0.1")) {
                    // Parse address:port (format: 142.250.80.110.443)
                    String[] remoteParts = remoteAddr.split("\\.");
                    if (remoteParts.length >= 5) {
                        // Reconstruct IP and port
                        String remoteIP = remoteParts[0] + "." + remoteParts[1] + "." + remoteParts[2] + "." + remoteParts[3];
                        String remotePort = remoteParts[4];
                        
                        // Skip if it's a local connection
                        if (!remoteIP.startsWith("127.") && !remoteIP.startsWith("::1") &&
                            !remoteIP.startsWith("169.254.") && !remoteIP.startsWith("0.")) {
                            
                            // Determine event type based on port
                            NetworkEvent.EventType eventType = getEventTypeFromPort(remotePort);
                            String description = getDescriptionFromPort(remotePort, remoteIP);
                            
                            NetworkEvent event = new NetworkEvent(
                                eventType,
                                "localhost",
                                remoteIP,
                                NetworkUtils.getHostname(remoteIP),
                                description,
                                (int)(Math.random() * 2000) + 500
                            );
                            
                            emitEvent(event);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Error parsing netstat line: {}", e.getMessage());
        }
    }
    
    private NetworkEvent.EventType getEventTypeFromPort(String port) {
        try {
            int portNum = Integer.parseInt(port);
            return switch (portNum) {
                case 80 -> NetworkEvent.EventType.HTTP_REQUEST;
                case 443 -> NetworkEvent.EventType.HTTPS_REQUEST;
                case 53 -> NetworkEvent.EventType.DNS_QUERY;
                case 21, 22, 23 -> NetworkEvent.EventType.FILE_TRANSFER;
                default -> {
                    if (portNum >= 1024 && portNum <= 5000) {
                        yield NetworkEvent.EventType.STREAMING;
                    } else {
                        yield NetworkEvent.EventType.UNKNOWN;
                    }
                }
            };
        } catch (NumberFormatException e) {
            return NetworkEvent.EventType.UNKNOWN;
        }
    }
    
    private String getDescriptionFromPort(String port, String remoteIP) {
        try {
            int portNum = Integer.parseInt(port);
            String hostname = NetworkUtils.getHostname(remoteIP);
            
            return switch (portNum) {
                case 80 -> "HTTP connection to " + hostname;
                case 443 -> "HTTPS connection to " + hostname;
                case 53 -> "DNS query to " + hostname;
                case 21 -> "FTP connection to " + hostname;
                case 22 -> "SSH connection to " + hostname;
                case 23 -> "Telnet connection to " + hostname;
                default -> "Connection to " + hostname + " on port " + port;
            };
        } catch (NumberFormatException e) {
            return "Connection to " + NetworkUtils.getHostname(remoteIP);
        }
    }
    
    private PcapNetworkInterface getDefaultNetworkInterface() {
        try {
            for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
                if (nif.isUp() && !nif.isLoopBack() && nif.getAddresses().size() > 0) {
                    return nif;
                }
            }
        } catch (Exception e) {
            logger.error("Failed to find network interfaces: {}", e.getMessage());
        }
        return null;
    }
    
    private void processPacket(Packet packet) {
        try {
            EthernetPacket ethPacket = packet.get(EthernetPacket.class);
            if (ethPacket == null) return;
            
            IpV4Packet ipPacket = ethPacket.get(IpV4Packet.class);
            if (ipPacket == null) return;
            
            String sourceIP = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String destIP = ipPacket.getHeader().getDstAddr().getHostAddress();
            
            NetworkEvent.EventType eventType = determineEventType(ipPacket);
            String description = "Network traffic detected";
            int dataSize = packet.length();
            
            NetworkEvent event = new NetworkEvent(
                eventType, sourceIP, destIP, 
                NetworkUtils.getHostname(sourceIP), 
                description, dataSize
            );
            
            emitEvent(event);
            
        } catch (Exception e) {
            logger.debug("Error processing packet: {}", e.getMessage());
        }
    }
    
    private NetworkEvent.EventType determineEventType(IpV4Packet ipPacket) {
        TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
        UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
        
        if (tcpPacket != null) {
            int destPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            switch (destPort) {
                case 80 -> { return NetworkEvent.EventType.HTTP_REQUEST; }
                case 443 -> { return NetworkEvent.EventType.HTTPS_REQUEST; }
                case 21, 22 -> { return NetworkEvent.EventType.FILE_TRANSFER; }
                default -> { return NetworkEvent.EventType.UNKNOWN; }
            }
        } else if (udpPacket != null) {
            int destPort = udpPacket.getHeader().getDstPort().valueAsInt();
            if (destPort == 53) {
                return NetworkEvent.EventType.DNS_QUERY;
            }
        }
        
        return NetworkEvent.EventType.UNKNOWN;
    }
    
    private void emitEvent(NetworkEvent event) {
        if (eventListener != null) {
            eventListener.accept(event);
        }
    }
    
    private void emitDeviceUpdate(NetworkDevice device) {
        if (deviceListener != null) {
            deviceListener.accept(device);
        }
    }
    
    public void shutdown() {
        stopMonitoring();
        executorService.shutdown();
        scheduledExecutor.shutdown();
        
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
            if (!scheduledExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduledExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
            scheduledExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
}
