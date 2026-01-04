# modules/ports.py
import subprocess
import logging

logger = logging.getLogger("AttackSurface")

def scan_ports(host: str) -> str:
    """
    Executes an Nmap scan against the target host and returns the raw output.
    Uses the -F (fast scan) option for efficiency.
    """
    
    # In a real system, Nmap must be installed and accessible via PATH
    nmap_command = [
        "nmap", 
        "-F",         # Fast scan (top 100 ports)
        "-sS",        # SYN Stealth Scan
        "-Pn",        # Skip host discovery (since we already check alive)
        "--open",     # Only show open ports
        "--host-timeout", "30s", # Timeout for the scan
        host
    ]
    
    try:
        logger.debug(f"Running Nmap for {host}: {' '.join(nmap_command)}")
        
        # Execute the command
        result = subprocess.run(
            nmap_command,
            capture_output=True,
            text=True,
            timeout=45,
            check=True
        )
        
        return result.stdout
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Nmap failed for {host}: {e.stderr}")
        return f"Error: Nmap scan failed. {e.stderr}"
    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap scan timed out for {host}")
        return "Error: Scan timed out."
    except FileNotFoundError:
        logger.critical("Error: Nmap command not found. Ensure Nmap is installed.")
        return "Error: Nmap not found."

