import sys
sys.path.insert(0, "/usr/share/attack-surface")

from modules.redteam.config import get_config
from modules.redteam.sliver import SliverClient
from modules.redteam.metasploit import MSFRPCClient

cfg = get_config("/root/.attack_surface/redteam.yaml")
print("Config loaded")
print("Metasploit password:", bool(cfg.metasploit.password))
print("Sliver CA cert:", cfg.sliver.ca_cert)
print("Validation:", cfg.validate())

# Test Sliver
sliver = SliverClient(cfg)
result = sliver.list_sessions()
print("Sliver sessions:", result)

# Test Metasploit
msf = MSFRPCClient(cfg.metasploit)
result = msf.connect()
print("MSF connect:", result.get("success"), result.get("error", "")[:80])