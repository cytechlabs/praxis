# SSH Security Management Documentation

## Overview

The SSH Security Management system provides comprehensive security controls for SSH connections within the Praxis application. This system allows administrators to define security policies, monitor security events, and manage host key verification for all SSH connections.

## Features

### 1. Security Policies
- **Policy Management**: Create, read, update, and delete SSH security policies
- **Configurable Settings**: Control authentication attempts, timeouts, encryption standards, and logging
- **Policy Assignment**: Assign policies to systems for consistent security enforcement

### 2. Security Logging
- **Event Tracking**: Monitor all SSH security events including authentication attempts, connections, and failures
- **Audit Trail**: Maintain detailed logs with timestamps, source IPs, and event details
- **Real-time Monitoring**: View recent security events and identify potential threats

### 3. Host Key Management
- **Key Verification**: Verify and manage SSH host keys to prevent man-in-the-middle attacks
- **Fingerprint Tracking**: Track host key fingerprints and their verification status
- **Key History**: Monitor when host keys were first and last seen

## Architecture

### Frontend Components

#### Main Page Component
- **File**: `src/pages/ssh-security.tsx`
- **Purpose**: Main interface for SSH security management
- **Features**: Tabbed interface with policies, logs, and host keys sections

#### API Integration
- **Service**: `src/services/sshSecurityService.ts`
- **API Routes**:
  - `/api/ssh-security/policies` - Policy CRUD operations
  - `/api/ssh-security/logs` - Security event logs
  - `/api/ssh-security/host-keys` - Host key management

### Backend Components

#### Database Models
- **SSHSecurityPolicy**: Stores security policy configurations
- **SSHSecurityLog**: Records security events and audit trails
- **SSHHostKey**: Manages host key verification data

#### API Endpoints
- **Routes**: `backend/app/api/routes/ssh_security.py`
- **Schemas**: `backend/app/api/schemas/ssh_security.py`
- **Service**: Enhanced `backend/app/services/ssh_service.py`

## User Interface

### Navigation
The SSH Security Management interface is accessible through the main sidebar navigation under "SSH Security".

### Tabs Overview

#### 1. Security Policies Tab
- **Purpose**: Manage SSH security policies
- **Actions**: Create, edit, delete policies
- **Display**: List of policies with key settings summary

#### 2. Security Logs Tab
- **Purpose**: View security event history
- **Display**: Table with timestamp, event type, system, user, status, and source IP
- **Filtering**: Recent events (last 50 by default)

#### 3. Host Keys Tab
- **Purpose**: Manage SSH host key verification
- **Actions**: Verify/unverify host keys
- **Display**: Table with hostname, key type, fingerprint, verification status

## Security Policy Configuration

### Policy Settings

#### Authentication Settings
- **Max Auth Tries**: Maximum number of authentication attempts (1-10)
- **Connection Timeout**: SSH connection timeout in seconds (5-300)
- **Idle Timeout**: Session idle timeout in seconds (60-3600)

#### Key Security
- **Minimum Key Size**: Required minimum SSH key size in bits (1024, 2048, 4096)
- **Host Key Verification**: Enable/disable host key verification requirement

#### Encryption Standards
- **Allowed Ciphers**: Configurable encryption ciphers (default: aes256-ctr,aes192-ctr,aes128-ctr)
- **Allowed MACs**: Message authentication codes (default: hmac-sha2-512,hmac-sha2-256)
- **Allowed KEX**: Key exchange algorithms (default: diffie-hellman-group-exchange-sha256)

#### Logging Options
- **Log Commands**: Enable/disable command execution logging
- **Log File Transfers**: Enable/disable file transfer logging

### Default Policy Settings
```json
{
  "max_auth_tries": 3,
  "connection_timeout": 10,
  "idle_timeout": 600,
  "require_host_key_verification": true,
  "minimum_key_size": 2048,
  "allowed_auth_methods": "publickey,password",
  "allowed_ciphers": "aes256-ctr,aes192-ctr,aes128-ctr",
  "allowed_macs": "hmac-sha2-512,hmac-sha2-256",
  "allowed_kex": "diffie-hellman-group-exchange-sha256",
  "log_commands": false,
  "log_file_transfers": true
}
```

## Security Event Types

### Authentication Events
- **auth_attempt**: SSH authentication attempt
- **auth_success**: Successful authentication
- **auth_failure**: Failed authentication

### Connection Events
- **connection_established**: SSH connection established
- **connection_closed**: SSH connection closed
- **connection_timeout**: Connection timeout occurred

### Security Events
- **host_key_verification**: Host key verification event
- **policy_violation**: Security policy violation
- **suspicious_activity**: Detected suspicious activity

### Command Events (if enabled)
- **command_execution**: Command executed via SSH
- **file_transfer**: File transfer operation

## Host Key Management

### Verification Process
1. **Automatic Detection**: Host keys are automatically detected during SSH connections
2. **Fingerprint Generation**: SHA-256 fingerprints are generated for each key
3. **Manual Verification**: Administrators can manually verify or unverify keys
4. **Policy Enforcement**: Unverified keys can be blocked based on policy settings

### Key Information Tracked
- **Hostname**: Target system hostname
- **Key Type**: SSH key type (RSA, ECDSA, Ed25519)
- **Public Key**: Full public key data
- **Fingerprint**: SHA-256 fingerprint
- **Verification Status**: Verified/unverified status
- **First Seen**: When the key was first encountered
- **Last Seen**: Most recent key usage

## API Reference

### Policy Management

#### Get All Policies
```http
GET /api/ssh-security/policies
```

#### Create Policy
```http
POST /api/ssh-security/policies
Content-Type: application/json

{
  "name": "High Security Policy",
  "description": "Strict security settings for production systems",
  "max_auth_tries": 2,
  "connection_timeout": 15,
  "require_host_key_verification": true,
  "minimum_key_size": 4096
}
```

#### Update Policy
```http
PUT /api/ssh-security/policies/{id}
Content-Type: application/json

{
  "name": "Updated Policy Name",
  "max_auth_tries": 3
}
```

#### Delete Policy
```http
DELETE /api/ssh-security/policies/{id}
```

### Security Logs

#### Get Security Logs
```http
GET /api/ssh-security/logs?limit=50&offset=0
```

### Host Key Management

#### Get Host Keys
```http
GET /api/ssh-security/host-keys
```

#### Update Host Key Verification
```http
PUT /api/ssh-security/host-keys/{id}
Content-Type: application/json

{
  "verified": true
}
```

## Security Best Practices

### Policy Configuration
1. **Enable Host Key Verification**: Always require host key verification in production
2. **Use Strong Key Sizes**: Minimum 2048-bit keys, prefer 4096-bit for high security
3. **Limit Authentication Attempts**: Set max auth tries to 3 or fewer
4. **Configure Appropriate Timeouts**: Balance security with usability
5. **Enable Logging**: Log file transfers and consider command logging for audit requirements

### Host Key Management
1. **Verify New Keys**: Always verify host keys when first encountered
2. **Monitor Key Changes**: Alert on host key changes which may indicate compromise
3. **Regular Audits**: Periodically review and verify host keys
4. **Document Verification**: Maintain records of key verification decisions

### Monitoring and Alerting
1. **Review Security Logs**: Regularly review security event logs
2. **Monitor Failed Attempts**: Watch for patterns in authentication failures
3. **Alert on Violations**: Set up alerts for policy violations
4. **Track Suspicious Activity**: Monitor for unusual connection patterns

## Troubleshooting

### Common Issues

#### Policy Not Applied
- **Cause**: System not assigned to policy
- **Solution**: Ensure system has ssh_security_policy_id set

#### Host Key Verification Failures
- **Cause**: Unverified host keys with strict policy
- **Solution**: Verify host keys or adjust policy settings

#### Connection Timeouts
- **Cause**: Timeout settings too restrictive
- **Solution**: Increase connection_timeout in policy

#### Authentication Failures
- **Cause**: Max auth tries exceeded
- **Solution**: Check max_auth_tries setting and user credentials

### Log Analysis
Use security logs to diagnose issues:
1. Filter by system_id to focus on specific systems
2. Look for patterns in event_type and success status
3. Check source_ip for potential security threats
4. Review event_details for additional context

## Integration with System Management

The SSH Security system integrates with the existing system management features:

1. **System Registration**: New systems can be assigned security policies during registration
2. **Credential Management**: Works with existing credential storage (passwords, keys, Vault)
3. **Connection Pooling**: Security policies are applied to all connections in the pool
4. **Monitoring Integration**: Security events can be correlated with system monitoring data

## Future Enhancements

### Planned Features
1. **Policy Templates**: Pre-defined policy templates for common use cases
2. **Automated Responses**: Automatic actions based on security events
3. **Integration Alerts**: Integration with external alerting systems
4. **Compliance Reporting**: Generate compliance reports based on security policies
5. **Risk Scoring**: Assign risk scores to systems based on security events

### API Enhancements
1. **Bulk Operations**: Bulk policy assignment and host key management
2. **Advanced Filtering**: Enhanced filtering options for logs and keys
3. **Export Capabilities**: Export security data for external analysis
4. **Webhook Support**: Real-time notifications via webhooks
