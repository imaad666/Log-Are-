package com.spynet.util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for network operations
 */
public class NetworkUtils {
    
    private static final Logger logger = LoggerFactory.getLogger(NetworkUtils.class);
    
    // Cache for hostname lookups to avoid repeated DNS queries
    private static final ConcurrentHashMap<String, String> hostnameCache = new ConcurrentHashMap<>();
    private static final long CACHE_EXPIRY = TimeUnit.MINUTES.toMillis(10); // 10 minutes
    private static final ConcurrentHashMap<String, Long> cacheTimestamps = new ConcurrentHashMap<>();
    
    /**
     * Get hostname for an IP address with caching
     */
    public static String getHostname(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            return "Unknown";
        }
        
        // Check cache first
        String cached = hostnameCache.get(ipAddress);
        Long timestamp = cacheTimestamps.get(ipAddress);
        
        if (cached != null && timestamp != null && 
            (System.currentTimeMillis() - timestamp) < CACHE_EXPIRY) {
            return cached;
        }
        
        // Perform lookup
        String hostname = performHostnameLookup(ipAddress);
        
        // Cache the result
        hostnameCache.put(ipAddress, hostname);
        cacheTimestamps.put(ipAddress, System.currentTimeMillis());
        
        return hostname;
    }
    
    private static String performHostnameLookup(String ipAddress) {
        try {
            // For demo purposes, provide known hostnames for common IPs
            String knownHostname = getKnownHostname(ipAddress);
            if (knownHostname != null) {
                return knownHostname;
            }
            
            // Actual DNS lookup (commented out for demo to avoid delays)
            // InetAddress addr = InetAddress.getByName(ipAddress);
            // return addr.getHostName();
            
            // For demo, return the IP if no known hostname
            return ipAddress;
            
        } catch (Exception e) {
            logger.debug("Failed to resolve hostname for {}: {}", ipAddress, e.getMessage());
            return ipAddress;
        }
    }
    
    private static String getKnownHostname(String ipAddress) {
        return switch (ipAddress) {
            case "142.250.191.14", "172.217.12.14" -> "google.com";
            case "104.16.249.249", "104.16.248.249" -> "cloudflare.com";
            case "31.13.64.35", "157.240.12.35" -> "facebook.com";
            case "140.82.112.4", "140.82.113.4" -> "github.com";
            case "17.253.144.10", "17.142.160.59" -> "apple.com";
            case "13.107.42.14", "40.76.4.15" -> "microsoft.com";
            case "8.8.8.8", "8.8.4.4" -> "dns.google";
            case "1.1.1.1", "1.0.0.1" -> "cloudflare-dns.com";
            case "192.168.1.1" -> "router.local";
            case "192.168.1.101" -> "iPhone-12";
            case "192.168.1.102" -> "MacBook-Pro";
            case "192.168.1.103" -> "Android-Tablet";
            case "192.168.1.104" -> "Smart-TV";
            default -> null;
        };
    }
    
    /**
     * Check if an IP address is in a private range
     */
    public static boolean isPrivateIP(String ipAddress) {
        try {
            InetAddress addr = InetAddress.getByName(ipAddress);
            return addr.isSiteLocalAddress() || addr.isLoopbackAddress();
        } catch (UnknownHostException e) {
            return false;
        }
    }
    
    /**
     * Get the network class of an IP address
     */
    public static String getNetworkClass(String ipAddress) {
        try {
            String[] parts = ipAddress.split("\\.");
            if (parts.length != 4) return "Invalid";
            
            int firstOctet = Integer.parseInt(parts[0]);
            
            if (firstOctet >= 1 && firstOctet <= 126) return "Class A";
            if (firstOctet >= 128 && firstOctet <= 191) return "Class B";
            if (firstOctet >= 192 && firstOctet <= 223) return "Class C";
            if (firstOctet >= 224 && firstOctet <= 239) return "Class D (Multicast)";
            if (firstOctet >= 240 && firstOctet <= 255) return "Class E (Reserved)";
            
            return "Unknown";
        } catch (Exception e) {
            return "Invalid";
        }
    }
    
    /**
     * Format MAC address
     */
    public static String formatMacAddress(String macAddress) {
        if (macAddress == null || macAddress.isEmpty()) {
            return "Unknown";
        }
        
        // Remove any existing separators and convert to uppercase
        String clean = macAddress.replaceAll("[:-]", "").toUpperCase();
        
        if (clean.length() != 12) {
            return macAddress; // Return original if invalid format
        }
        
        // Format as XX:XX:XX:XX:XX:XX
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < clean.length(); i += 2) {
            if (i > 0) formatted.append(":");
            formatted.append(clean, i, i + 2);
        }
        
        return formatted.toString();
    }
    
    /**
     * Get device vendor from MAC address (OUI lookup)
     */
    public static String getDeviceVendor(String macAddress) {
        if (macAddress == null || macAddress.length() < 8) {
            return "Unknown";
        }
        
        // Extract OUI (first 3 octets)
        String oui = macAddress.replaceAll("[:-]", "").substring(0, 6).toUpperCase();
        
        // Common OUI mappings for demo
        return switch (oui) {
            case "AABBCC" -> "Apple Inc.";
            case "112233" -> "Dell Inc.";
            case "778899" -> "Samsung Electronics";
            case "DDEEFF" -> "LG Electronics";
            case "001122" -> "Cisco Systems";
            case "AABBDD" -> "Intel Corporate";
            default -> "Unknown Vendor";
        };
    }
    
    /**
     * Clear hostname cache
     */
    public static void clearHostnameCache() {
        hostnameCache.clear();
        cacheTimestamps.clear();
        logger.info("Hostname cache cleared");
    }
}
