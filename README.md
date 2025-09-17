# 🕵️ NetworkSpy - Network Intelligence Dashboard

A spy-themed network monitoring application built in Java that provides real-time visibility into your WiFi network traffic and connected devices.

## 🚀 Features

- **Real-time Network Monitoring**: Track all network traffic and connections in real-time
- **Device Discovery**: Automatically detect and categorize devices connecting to your network
- **Spy-themed UI**: Dark, terminal-like interface with green accent colors for that authentic spy feel
- **Traffic Analysis**: Monitor HTTP/HTTPS requests, DNS queries, file transfers, and media streaming
- **Device Intelligence**: Identify device types (phones, laptops, tablets, IoT devices, etc.)
- **Live Event Log**: See every network event as it happens with timestamps and details
- **Connection Tracking**: Monitor when devices connect and disconnect from your network

## 🛠️ Technology Stack

- **Java 17+**: Modern Java with latest features
- **JavaFX**: Rich desktop UI framework
- **Maven**: Dependency management and build system
- **pcap4j**: Packet capture library for network monitoring
- **SLF4J + Logback**: Logging framework

## 📋 Prerequisites

Before running NetworkSpy, ensure you have:

1. **Java 17 or higher** installed
2. **Maven** installed
3. **Administrative privileges** (required for packet capture)
4. **Network interface access** (the application needs to monitor network traffic)

### macOS Setup
```bash
# Install Java 17+ (if not already installed)
brew install openjdk@17

# Install Maven (if not already installed)
brew install maven

# Note: You may need to run the application with sudo for packet capture
```

### Windows Setup
- Install Java 17+ from Oracle or OpenJDK
- Install Maven from Apache Maven website
- Install WinPcap or Npcap for packet capture support
- Run Command Prompt as Administrator

### Linux Setup
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install openjdk-17-jdk maven libpcap-dev

# CentOS/RHEL/Fedora
sudo yum install java-17-openjdk-devel maven libpcap-devel
```

## 🏃‍♂️ Quick Start

1. **Clone and build the project**:
```bash
cd /path/to/project
mvn clean compile
```

2. **Run the application**:
```bash
# Using Maven
mvn javafx:run

# Or compile and run directly
mvn clean package
java -jar target/network-spy-1.0-SNAPSHOT-shaded.jar
```

3. **Start monitoring**:
   - Click the "🚀 START SCAN" button in the interface
   - Grant necessary permissions when prompted
   - Watch as network events appear in real-time!

## 🎮 How to Use

### Main Interface
- **Left Panel**: Real-time network events log showing all traffic
- **Right Panel**: Connected devices list with device information
- **Top Controls**: Start/stop monitoring, clear logs, export data
- **Bottom Status**: Current monitoring status and statistics

### Event Types
- 🔗 **Device Connected**: New device joined the network
- ❌ **Device Disconnected**: Device left the network
- 🌐 **HTTP Request**: Unencrypted web traffic
- 🔒 **HTTPS Request**: Encrypted web traffic
- 🔍 **DNS Query**: Domain name resolution
- 📁 **File Transfer**: FTP/file sharing activity
- 📺 **Media Streaming**: Video/audio streaming detected

### Device Categories
- 📱 **Mobile Phones**: iOS and Android devices
- 💻 **Laptops**: Portable computers
- 🖥️ **Desktops**: Desktop computers
- 📱 **Tablets**: iPad and Android tablets
- 📡 **Routers**: Network infrastructure
- 🏠 **IoT Devices**: Smart home devices
- 🎮 **Game Consoles**: Gaming devices
- 📺 **Smart TVs**: Connected televisions

## 🔧 Configuration

The application includes a demo mode that simulates network traffic for testing purposes. In production environments with proper permissions, it will capture real network packets.

### Customization Options
- Modify colors in `src/main/resources/spy-theme.css`
- Adjust monitoring intervals in `NetworkMonitorService.java`
- Add custom device detection rules in `NetworkUtils.java`

## 🚨 Important Notes

### Permissions
- **Root/Administrator access** may be required for packet capture
- Some antivirus software may flag network monitoring tools
- Ensure you have permission to monitor the network you're scanning

### Privacy & Legal
- Only monitor networks you own or have explicit permission to monitor
- Be aware of local laws regarding network monitoring
- This tool is for educational and legitimate network administration purposes

### Performance
- The application limits event history to prevent memory issues
- Continuous monitoring may impact system performance
- Consider monitoring intervals based on your needs

## 🐛 Troubleshooting

### Common Issues

**"No network interface found"**
- Ensure you have network interfaces available
- Try running with administrator privileges
- Check that pcap4j dependencies are properly installed

**"Permission denied" errors**
- Run the application with elevated privileges (sudo on macOS/Linux, "Run as Administrator" on Windows)
- Ensure your user has access to network interfaces

**JavaFX runtime errors**
- Ensure JavaFX modules are available in your Java installation
- Use a JDK that includes JavaFX or install it separately

## 🤝 Contributing

This is a demonstration project, but feel free to:
- Report bugs or issues
- Suggest new features
- Submit pull requests
- Improve documentation

## 📜 License

This project is for educational and demonstration purposes. Please ensure you comply with local laws and regulations when using network monitoring tools.

## 🎯 Future Enhancements

- Export functionality for logs and reports
- Advanced filtering and search capabilities
- Network topology visualization
- Threat detection and alerting
- Historical data analysis
- Mobile app companion
- Custom alerting rules
- Integration with security tools

---

**⚠️ Disclaimer**: This tool is designed for legitimate network monitoring and educational purposes only. Always ensure you have proper authorization before monitoring any network traffic.
