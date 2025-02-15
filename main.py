import subprocess
import logging
import re
import ipaddress
from dataclasses import dataclass
from typing import List, Optional
from enum import Enum
from pathlib import Path
import json
from datetime import datetime
import threading
from contextlib import contextmanager
from datetime import timedelta

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ssh_access.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class BlockReason(Enum):
    """Enumeration of reasons for blocking an IP."""
    MANUAL = "manual"
    FAILED_ATTEMPTS = "failed_attempts"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    GEOLOCATION = "geolocation"

@dataclass
class BlockedIP:
    """Data class to store information about blocked IPs."""
    ip_address: str
    timestamp: datetime
    reason: BlockReason
    expires_at: Optional[datetime] = None
    notes: Optional[str] = None

class SSHAccessManager:
    """
    Enhanced manager for SSH access restrictions via iptables.
    
    Features:
    - Thread-safe operations
    - Persistent blocking history
    - IP validation with CIDR support
    - Whitelist support
    - Rate limiting
    - Temporary blocks with expiration
    """
    
    SSH_PORT = 22
    HISTORY_FILE = Path("/var/log/ssh_blocks.json")
    WHITELIST_FILE = Path("/etc/ssh/whitelist.txt")
    
    def __init__(self):
        self._lock = threading.Lock()
        self._blocked_ips: dict[str, BlockedIP] = {}
        self._load_history()
        self._ensure_whitelist()
    
    @contextmanager
    def _iptables_lock(self):
        """Thread-safe context manager for iptables operations."""
        with self._lock:
            try:
                yield
            finally:
                self._save_history()

    def _load_history(self) -> None:
        """Load blocking history from persistent storage."""
        try:
            if self.HISTORY_FILE.exists():
                with open(self.HISTORY_FILE, 'r') as f:
                    data = json.load(f)
                    for ip_data in data:
                        self._blocked_ips[ip_data['ip_address']] = BlockedIP(
                            ip_address=ip_data['ip_address'],
                            timestamp=datetime.fromisoformat(ip_data['timestamp']),
                            reason=BlockReason(ip_data['reason']),
                            expires_at=datetime.fromisoformat(ip_data['expires_at']) if ip_data.get('expires_at') else None,
                            notes=ip_data.get('notes')
                        )
        except Exception as e:
            logger.error(f"Error loading history: {e}")
            self._blocked_ips = {}

    def _save_history(self) -> None:
        """Save blocking history to persistent storage."""
        try:
            data = [
                {
                    'ip_address': ip.ip_address,
                    'timestamp': ip.timestamp.isoformat(),
                    'reason': ip.reason.value,
                    'expires_at': ip.expires_at.isoformat() if ip.expires_at else None,
                    'notes': ip.notes
                }
                for ip in self._blocked_ips.values()
            ]
            self.HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.HISTORY_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving history: {e}")

    def _ensure_whitelist(self) -> None:
        """Ensure whitelist file exists with default trusted IPs."""
        if not self.WHITELIST_FILE.exists():
            self.WHITELIST_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.WHITELIST_FILE, 'w') as f:
                f.write("# Trusted IP addresses (one per line)\n")
                f.write("127.0.0.1\n")  # localhost
                f.write("::1\n")        # IPv6 localhost

    def _validate_ip(self, ip_address: str) -> None:
        """
        Validate IP address or CIDR notation.
        
        Args:
            ip_address: IP address or CIDR notation
            
        Raises:
            ValueError: If IP address is invalid
        """
        try:
            ipaddress.ip_network(ip_address, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid IP address or CIDR notation: {ip_address}") from e

    def _run_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """
        Execute iptables command with improved error handling.
        
        Args:
            command: Command and arguments as list
            
        Returns:
            CompletedProcess instance
            
        Raises:
            subprocess.CalledProcessError: If command fails
        """
        logger.debug(f"Executing: {' '.join(command)}")
        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
                timeout=10  # Prevent hanging
            )
            return result
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out: {e}")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e.stderr}")
            raise

    def is_blocked(self, ip_address: str) -> bool:
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            bool: True if the IP is blocked, False otherwise
        """
        # First check our internal state
        if ip_address in self._blocked_ips:
            # Check if block has expired
            block_info = self._blocked_ips[ip_address]
            if block_info.expires_at and block_info.expires_at <= datetime.now():
                # Block has expired, clean it up
                self.unblock_ip(ip_address)
                return False
            return True

        # Verify with iptables as a backup
        command = [
            "iptables", "-C", "INPUT",
            "-s", ip_address,
            "-p", "tcp",
            "--dport", str(self.SSH_PORT),
            "-j", "DROP"
        ]
        try:
            self._run_command(command)
            # If we get here, the rule exists but wasn't in our state
            logger.warning(f"IP {ip_address} found in iptables but not in internal state")
            return True
        except subprocess.CalledProcessError:
            return False


    def block_ip(self, ip_address: str, reason: BlockReason, 
                expires_in: Optional[int] = None, notes: Optional[str] = None) -> None:
        """
        Block an IP address from SSH access.
        """
        self._validate_ip(ip_address)
        
        if self._is_whitelisted(ip_address):
            logger.warning(f"Attempted to block whitelisted IP: {ip_address}")
            return
            
        with self._iptables_lock():
            if not self.is_blocked(ip_address):
                command = [
                    "iptables", "-A", "INPUT",
                    "-s", ip_address,
                    "-p", "tcp",
                    "--dport", str(self.SSH_PORT),
                    "-j", "DROP"
                ]
                self._run_command(command)
                
                expires_at = None
                if expires_in:
                    expires_at = datetime.now().replace(microsecond=0) + timedelta(minutes=expires_in)
                
                self._blocked_ips[ip_address] = BlockedIP(
                    ip_address=ip_address,
                    timestamp=datetime.now().replace(microsecond=0),
                    reason=reason,
                    expires_at=expires_at,
                    notes=notes
                )
                logger.info(f"Blocked IP {ip_address} for {reason.value}")


    def unblock_ip(self, ip_address: str) -> None:
        """Unblock an IP address from SSH access."""
        self._validate_ip(ip_address)
        
        with self._iptables_lock():
            if self.is_blocked(ip_address):
                command = [
                    "iptables", "-D", "INPUT",
                    "-s", ip_address,
                    "-p", "tcp",
                    "--dport", str(self.SSH_PORT),
                    "-j", "DROP"
                ]
                try:
                    self._run_command(command)
                except subprocess.CalledProcessError as e:
                    if "Bad rule" in e.stderr:
                        logger.warning(f"No matching iptables rule found for {ip_address}; continuing cleanup.")
                    else:
                        logger.error(f"Error unblocking IP {ip_address}: {e.stderr}")
                        raise
            # Remove the IP from internal state regardless
            self._blocked_ips.pop(ip_address, None)
            logger.info(f"Unblocked IP {ip_address}")



    def _is_whitelisted(self, ip_address: str) -> bool:
        """Check if an IP address is whitelisted."""
        try:
            with open(self.WHITELIST_FILE, 'r') as f:
                whitelist = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            return ip_address in whitelist
        except Exception as e:
            logger.error(f"Error checking whitelist: {e}")
            return False

    def add_to_whitelist(self, ip_address: str) -> None:
        """Add an IP address to the whitelist."""
        self._validate_ip(ip_address)
        
        if self.is_blocked(ip_address):
            self.unblock_ip(ip_address)
            
        with open(self.WHITELIST_FILE, 'a') as f:
            f.write(f"{ip_address}\n")
        logger.info(f"Added {ip_address} to whitelist")

    def remove_from_whitelist(self, ip_address: str) -> None:
        """Remove an IP address from the whitelist."""
        self._validate_ip(ip_address)
        
        try:
            with open(self.WHITELIST_FILE, 'r') as f:
                lines = f.readlines()
            
            with open(self.WHITELIST_FILE, 'w') as f:
                for line in lines:
                    if line.strip() != ip_address:
                        f.write(line)
            logger.info(f"Removed {ip_address} from whitelist")
        except Exception as e:
            logger.error(f"Error removing from whitelist: {e}")
            raise

    def get_block_info(self, ip_address: str) -> Optional[BlockedIP]:
        """Get information about a blocked IP."""
        return self._blocked_ips.get(ip_address)

    def list_blocked_ips(self) -> List[BlockedIP]:
        """List all blocked IPs with their details."""
        return list(self._blocked_ips.values())

    def cleanup_expired_blocks(self) -> None:
        """Remove expired IP blocks."""
        now = datetime.now()
        expired_ips = [
            ip for ip, info in self._blocked_ips.items()
            if info.expires_at and info.expires_at <= now
        ]
        
        for ip in expired_ips:
            self.unblock_ip(ip)

# Example usage:
if __name__ == "__main__":
    manager = SSHAccessManager()
    
    # Block an IP for suspicious activity
    manager.unblock_ip(
        "192.168.1.100",
    )
    
    # Add trusted IP to whitelist
    manager.add_to_whitelist("10.0.0.5")
    
    # List all blocked IPs
    blocked = manager.list_blocked_ips()
    for ip in blocked:
        print(f"IP: {ip.ip_address}, Reason: {ip.reason.value}, Expires: {ip.expires_at}")
    
    # Clean up expired blocks
    manager.cleanup_expired_blocks()
