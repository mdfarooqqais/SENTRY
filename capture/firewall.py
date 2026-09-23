import subprocess
import time

# Keep track of blocked IPs to avoid redundant firewall rules
blocked_ips = set()

def block_ip(ip_address, reason="Suspicious Activity"):
    """
    Blocks an IP address using Windows Defender Firewall.
    Must be run as Administrator.
    """
    # Don't block local loopback or already blocked IPs
    if ip_address in blocked_ips or ip_address in ["127.0.0.1", "localhost", "0.0.0.0"]:
        return False
        
    try:
        rule_name_in = f"SENTRY_BLOCK_IN_{ip_address}"
        rule_name_out = f"SENTRY_BLOCK_OUT_{ip_address}"
        
        # Block incoming traffic
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip_address}'
        subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Block outgoing traffic
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip_address}'
        subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        blocked_ips.add(ip_address)
        print(f"\n[\u2718] ACTIVE MITIGATION: Windows Firewall rule added! BLOCKED IP {ip_address} (Reason: {reason})")
        return True
        
    except subprocess.CalledProcessError:
        print(f"\n[!] MITIGATION FAILED: Could not block {ip_address}. Are you running the terminal as Administrator?")
        return False

