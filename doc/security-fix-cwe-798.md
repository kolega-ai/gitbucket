# Security Fix: CWE-798 Hardcoded Credentials

## Overview

This document describes the security vulnerability fix for CWE-798 (Use of Hard-coded Credentials) in GitBucket's database initialization process.

## Vulnerability Description

**Rule:** `secrets.Hex High Entropy String`  
**Severity:** High  
**File:** `src/main/resources/update/gitbucket-core_4.0.xml`  
**CWE:** CWE-798  
**OWASP:** A07:2021  

### Original Issue

The GitBucket 4.0.0 database migration contained a hardcoded SHA-1 password hash:

```xml
<column name="PASSWORD" value="dc76e9f0c0006e8f919e0c515c66dbba3982f785"/>
```

This hash represents the password "root" and was used to create the default admin account. The vulnerability had several security implications:

1. **Predictable Credentials**: Default username/password of `root/root`
2. **Source Code Exposure**: Credentials visible in public repository
3. **Weak Hashing**: SHA-1 is cryptographically weak
4. **Attack Vector**: Attackers could target fresh installations

## Fix Implementation

### 1. Custom Migration Class

Replaced the hardcoded XML insert with a custom Liquibase migration:

**File:** `src/main/scala/gitbucket/core/util/AdminAccountMigration.scala`

Key features:
- Environment variable support (`GITBUCKET_ADMIN_PASSWORD`)
- System property support (`gitbucket.admin.password`)
- Secure random password generation as fallback
- PBKDF2-SHA256 hashing with 100,000 iterations
- Idempotent execution (won't recreate existing accounts)
- Proper logging without credential exposure

### 2. Database Schema Update

Updated the `ACCOUNT.PASSWORD` column size from `varchar(40)` to `varchar(200)` to accommodate PBKDF2 hashes.

### 3. Migration XML Changes

**Before:**
```xml
<insert tableName="ACCOUNT">
  <column name="PASSWORD" value="dc76e9f0c0006e8f919e0c515c66dbba3982f785"/>
  <!-- ... other columns ... -->
</insert>
```

**After:**
```xml
<!-- 
  SECURITY FIX: Replaced hardcoded password hash with custom migration
  See: AdminAccountMigration.scala
  Resolves: CWE-798 (Use of Hard-coded Credentials)
-->
<customChange class="gitbucket.core.util.AdminAccountMigration"/>
```

### 4. Documentation Updates

Updated `README.md` to document the new admin password configuration options and removed references to default credentials.

## Password Resolution Priority

The fix follows a clear priority chain for password resolution:

1. **Environment Variable** (Highest Priority)
   - `GITBUCKET_ADMIN_PASSWORD=your-secure-password`
   - Recommended for container deployments

2. **System Property**
   - `-Dgitbucket.admin.password=your-secure-password`
   - Useful for traditional deployments

3. **Auto-Generated** (Fallback)
   - 16-character cryptographically secure random password
   - Logged once during initial setup
   - Uses character set: `A-Z a-z 0-9 !@#$%^&*`

## Security Improvements

| Vulnerability | Status | Solution |
|--------------|--------|----------|
| CWE-798: Hardcoded Credentials | ✅ **FIXED** | Removed hardcoded hash, added configuration options |
| CWE-328: Weak Hash Algorithm | ✅ **FIXED** | PBKDF2-SHA256 with 100k iterations |
| CWE-521: Weak Password Requirements | ⚠️ **MITIGATED** | Strong random generation, user can set secure passwords |
| CWE-532: Log File Exposure | ⚠️ **MITIGATED** | Generated passwords logged once only |

## Usage Examples

### Container Deployment

```yaml
# Docker Compose
services:
  gitbucket:
    image: gitbucket/gitbucket
    environment:
      - GITBUCKET_ADMIN_PASSWORD=${SECURE_PASSWORD}
    ports:
      - "8080:8080"
```

```yaml
# Kubernetes
apiVersion: v1
kind: Secret
metadata:
  name: gitbucket-admin
type: Opaque
stringData:
  password: "your-secure-password"
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: gitbucket
          env:
            - name: GITBUCKET_ADMIN_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: gitbucket-admin
                  key: password
```

### Traditional Deployment

```bash
# Environment variable
export GITBUCKET_ADMIN_PASSWORD=your-secure-password
java -jar gitbucket.war

# System property
java -Dgitbucket.admin.password=your-secure-password -jar gitbucket.war

# Auto-generated (check logs for password)
java -jar gitbucket.war
```

## Migration Compatibility

### Existing Installations

- **No Impact**: Existing installations that have already run the 4.0.0 migration are unaffected
- **Password Unchanged**: Current admin passwords remain as users have configured them
- **No Re-execution**: Migration is idempotent and won't recreate existing accounts

### New Installations

- **Secure by Default**: No hardcoded credentials
- **Flexible Configuration**: Multiple password source options
- **Modern Cryptography**: PBKDF2-SHA256 from initial setup

## Testing

The fix includes comprehensive test coverage in `AdminAccountMigrationSpec.scala`:

- Password generation uniqueness and strength
- Configuration option validation  
- Schema compatibility verification
- Security improvement documentation

## Rollback Plan

If rollback is needed:

1. The custom migration supports proper Liquibase rollback
2. Rollback removes the admin account created by the migration
3. Original XML can be restored if necessary (not recommended for security)

## Recommendations

1. **Set Explicit Password**: Always set `GITBUCKET_ADMIN_PASSWORD` for production
2. **Use Secret Management**: Integrate with Docker secrets, Kubernetes secrets, etc.
3. **Change Default Password**: If using generated password, change it after first login
4. **Monitor Logs**: Check startup logs for generated passwords in development
5. **Regular Updates**: Keep GitBucket updated for latest security fixes

## References

- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [OWASP A07:2021 – Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [GitBucket Installation Guide](../README.md#admin-password-configuration)