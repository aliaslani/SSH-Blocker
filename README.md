# SSH Access Manager

A robust Python library for managing SSH access restrictions using iptables. This tool provides a secure and flexible way to manage SSH access control with features like IP blocking, whitelisting, and temporary restrictions.

## Features

- **Thread-safe Operations**: Safe for use in multi-threaded environments
- **Persistent Storage**: Maintains blocking history across restarts
- **IP Validation**: Supports both IPv4 and IPv6 addresses with CIDR notation
- **Whitelist Management**: Maintain a list of trusted IPs that cannot be blocked
- **Temporary Blocks**: Set expiration times for temporary IP blocks
- **Detailed Logging**: Comprehensive logging of all operations
- **Block Reasons**: Track and categorize reasons for IP blocks
- **Automatic Cleanup**: Automatically removes expired blocks

## Prerequisites

- Python 3.9 or higher
- Root/sudo access (required for iptables operations)
- Linux system with iptables installed

## Installation

1. Clone the repository:
```bash
https://github.com/aliaslani/SSH-Blocker.git
cd SSH-Blocker
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

The tool uses several configuration files:

- `/var/log/ssh_blocks.json`: Stores blocking history
- `/etc/ssh/whitelist.txt`: Contains whitelisted IP addresses
- `/var/log/ssh_access.log`: Log file for operations

These paths can be modified in the `SSHAccessManager` class if needed.

## Usage

### Basic Usage

```python
from ssh_access_manager import SSHAccessManager, BlockReason

# Initialize the manager
manager = SSHAccessManager()

# Block an IP address
manager.block_ip(
    "192.168.1.100",
    reason=BlockReason.SUSPICIOUS_ACTIVITY,
    expires_in=60,  # minutes
    notes="Multiple failed login attempts"
)

# Unblock an IP address
manager.unblock_ip("192.168.1.100")

# Add IP to whitelist
manager.add_to_whitelist("10.0.0.5")

# List all blocked IPs
blocked_ips = manager.list_blocked_ips()
```

### Advanced Usage

#### Temporary Blocks

```python
# Block IP for 2 hours
manager.block_ip(
    "192.168.1.100",
    reason=BlockReason.FAILED_ATTEMPTS,
    expires_in=120,
    notes="Temporary block due to failed login attempts"
)
```

#### Managing Whitelist

```python
# Add to whitelist
manager.add_to_whitelist("10.0.0.5")

# Remove from whitelist
manager.remove_from_whitelist("10.0.0.5")
```

#### Checking Block Status

```python
# Get information about a blocked IP
info = manager.get_block_info("192.168.1.100")
if info:
    print(f"Blocked at: {info.timestamp}")
    print(f"Reason: {info.reason}")
    print(f"Expires at: {info.expires_at}")
```

#### Cleanup

```python
# Remove all expired blocks
manager.cleanup_expired_blocks()
```

## Block Reasons

The tool supports several predefined reasons for blocking:

- `BlockReason.MANUAL`: Manual block by administrator
- `BlockReason.FAILED_ATTEMPTS`: Multiple failed login attempts
- `BlockReason.SUSPICIOUS_ACTIVITY`: Suspicious behavior detected
- `BlockReason.GEOLOCATION`: Geographic restriction

## Logging

The tool logs all operations to both file and console. Logs can be found at `/var/log/ssh_access.log` by default.

Example log output:
```
2025-02-15 10:30:15 - ssh_access_manager - INFO - Blocked IP 192.168.1.100 for suspicious_activity
2025-02-15 10:35:20 - ssh_access_manager - INFO - Added 10.0.0.5 to whitelist
```

## Security Considerations

- Always run the tool with appropriate permissions (root/sudo)
- Regularly backup the whitelist and blocking history
- Monitor the logs for unusual activity
- Keep the Python environment and dependencies updated
- Consider implementing additional security measures like rate limiting

## Error Handling

The tool includes comprehensive error handling for common scenarios:

- Invalid IP addresses
- Network timeouts
- Permission errors
- File system errors
- Command execution failures

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

Ali Aslani - Initial work - [aliaslani](https://github.com/aliaslani)

## Acknowledgments

- The iptables development team
- Python security community
- All contributors to this project

## Support

For support, please open an issue in the GitHub repository or contact the maintainers directly.# SSH-Blocker
