import socket
                                                                                  
CRITICAL_PORTS = {
    # SSH/Remote Access
    22: "ssh", 
    3389: "ms-rdp", # Remote Desktop
    5900: "vnc",    # VNC
    
    # File Transfer
    21: "ftp",      # FTP
    139: "netbios-ssn", # Samba/NetBIOS
    445: "microsoft-ds", # SMB/Windows File Share
    
    # Web & API
    8080: "http-alt",
    8088: "http-proxy",
    8443: "https-alt",
    
    # Databases
    3306: "mysql",
    5432: "postgresql",
    27017: "mongodb",
    6379: "redis",
    
    # Email
    25: "smtp",
    587: "submission",
    110: "pop3",
    143: "imap",
    993: "imaps",
    995: "pop3s",
    
    # Other Management/Services
    23: "telnet",
    53: "dns", # Important if it's an internal resolver
    631: "ipp", # Printing
    1194: "openvpn",
    1723: "pptp",
    2049: "nfs",
    2375: "docker-daemon-http", # Unsecured Docker
    2376: "docker-daemon-https", # Secured Docker
    9000: "php-fpm", # Often used for FastCGI/Application
    9200: "elasticsearch", # Default Elasticsearch
    10000: "webmin/usermin", # Common Web-based management panel
    50000: "sap-control", # Common for SAP/JIRA/Confluence type services
    50001: "sap-control-alt",
}
                                                                                  
TIMEOUT = 1.5
                                                                                  
def deep_scan_origin_ports(origin_ip: str) -> dict:                                   
    print(f"[+] Origin deep port scan on {origin_ip}")
                                                                                      
    open_ports = []                                                                                                                                                     
    for port, service in CRITICAL_PORTS.items():                                          
        try:                                                                                  
            sock = socket.create_connection((origin_ip, port), timeout=TIMEOUT)
            sock.close()                                                                                                                                                        
            open_ports.append({                                                                   
                "port": port,
                "service": service                                                            
            })
                                                                                          
        except Exception:
            continue                                                                                                                                                    
    return {                                                                              
        "type": "origin_port_deep_scan",
        "origin_ip": origin_ip,                                                           
        "open_ports": open_ports
    }                                                                             
                                                                                  
def origin_port_scan_to_events(scan_result: dict) -> list:                            
    events = []
                                                                                      
    origin_ip = scan_result.get("origin_ip")
                                                                                      
    for port in scan_result.get("open_ports", []):
        events.append({                                                                       
            "type": "origin_open_management_port",
            "origin_ip": origin_ip,                                                           
            "port": port.get("port"),
            "service": port.get("service"),                                               
        })
                                                                                      
    return events

