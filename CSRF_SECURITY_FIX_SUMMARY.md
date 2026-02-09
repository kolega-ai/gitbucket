# CSRF Security Fix for GitBucket SSH Key Management

## Security Vulnerability Fixed

**CWE-352: Cross-Site Request Forgery (CSRF)**

The SSH key management functionality in GitBucket was vulnerable to CSRF attacks that could allow an attacker to:
1. Add their own SSH keys to a victim's account (gaining repository access)
2. Delete existing SSH keys from a victim's account (causing access disruption)

## Root Cause Analysis

The vulnerable file `src/main/twirl/gitbucket/core/account/ssh.scala.html` contained:

### 1. Form without CSRF Protection
```html
<form method="POST" action="@context.path/@account.userName/_ssh">
  <!-- No CSRF token -->
  <input type="text" name="title"/>
  <textarea name="publicKey"></textarea>
  <input type="submit" value="Add"/>
</form>
```

### 2. Insecure DELETE via GET
```html
<a href="@context.path/@account.userName/_ssh/delete/@key.sshKeyId" class="btn btn-danger">
  Delete
</a>
```

**Impact:** An attacker could craft a malicious webpage that automatically submits these forms when a logged-in GitBucket user visits the page.

## Security Fix Implementation

### 1. CSRF Protection Infrastructure

#### Created `CsrfUtil.scala`
- **Purpose:** Secure token generation and validation
- **Features:**
  - Cryptographically secure random token generation (32 bytes, Base64-URL encoded)
  - Session-based token storage
  - Constant-time string comparison (prevents timing attacks)
  - Support for both form parameters and HTTP headers
  
#### Enhanced `Context.scala`
- **Added CSRF token methods:**
  - `csrfToken`: Lazy-loaded token for current session
  - `csrfTokenInput`: Generates hidden form input with token
  - `csrfTokenName`: Provides parameter name for JavaScript

#### Created `CsrfProtection.scala`
- **Purpose:** Controller trait for automatic CSRF validation
- **Features:**
  - Automatic validation on POST/PUT/DELETE/PATCH requests
  - Configurable excluded paths (for API endpoints)
  - Comprehensive logging for security monitoring

### 2. Template Security Updates

#### Updated `ssh.scala.html`
```html
<!-- BEFORE (vulnerable) -->
<form method="POST" action="@context.path/@account.userName/_ssh">
  <input type="text" name="title"/>
  <!-- No CSRF token -->
</form>
<a href="@context.path/@account.userName/_ssh/delete/@key.sshKeyId">Delete</a>

<!-- AFTER (secure) -->
<form method="POST" action="@context.path/@account.userName/_ssh">
  @context.csrfTokenInput  <!-- CSRF protection added -->
  <input type="text" name="title" maxlength="100"/>
</form>
<!-- Changed from GET link to POST form with CSRF protection -->
<form method="POST" action="@context.path/@account.userName/_ssh/delete/@key.sshKeyId">
  @context.csrfTokenInput
  <button type="submit" onclick="return confirm('Are you sure?')">Delete</button>
</form>
```

### 3. Controller Security Updates

#### Updated `AccountController.scala`
```scala
// Added CSRF protection trait
class AccountController extends ... with CsrfProtection

// Changed insecure GET delete to secure POST
post("/:userName/_ssh/delete/:id")(oneselfOnly {
  val userName = params("userName")
  val sshKeyId = params("id").toInt
  deletePublicKey(userName, sshKeyId)
  redirect(s"/$userName/_ssh")
})

// Added deprecated GET handler for backwards compatibility
get("/:userName/_ssh/delete/:id")(oneselfOnly {
  val userName = params("userName")
  logger.warn(s"Deprecated GET delete endpoint accessed by user $userName")
  redirect(s"/$userName/_ssh?error=invalid_request")
})
```

## Security Improvements

### Defense in Depth
1. **Token-based CSRF protection** - Prevents cross-site request forgery
2. **Secure HTTP methods** - Changed DELETE from GET to POST 
3. **User confirmation** - Added JavaScript confirmation for delete operations
4. **Input validation** - Added maxlength and placeholder attributes
5. **Security logging** - Comprehensive audit trail for security events
6. **Constant-time comparison** - Prevents timing attacks on token validation

### User Experience Enhancements
- Better form validation with placeholders and help text
- Confirmation dialog prevents accidental deletions
- Improved accessibility with proper labels
- Enhanced visual feedback for security operations

## Testing

### Comprehensive Test Suite
Created `CsrfUtilSpec.scala` with test coverage for:
- Token generation uniqueness and format
- Session-based token management
- Request validation scenarios
- Edge cases and error conditions

### Security Test Scenarios
1. **Valid CSRF token** - Forms submit successfully
2. **Missing CSRF token** - Returns 403 Forbidden
3. **Invalid CSRF token** - Returns 403 Forbidden
4. **Token in header** - Alternative token delivery method works
5. **Deprecated GET delete** - Safely redirects without deletion

## Backwards Compatibility

The fix maintains backwards compatibility by:
1. **Graceful degradation** - Old GET delete links redirect safely instead of crashing
2. **API preservation** - Existing API endpoints with Authorization headers are excluded
3. **Session handling** - No changes to existing session management
4. **Template compatibility** - All existing template functionality preserved

## Files Modified/Created

### New Files
- `src/main/scala/gitbucket/core/util/CsrfUtil.scala` - CSRF token utilities
- `src/main/scala/gitbucket/core/controller/CsrfProtection.scala` - Controller protection trait
- `src/test/scala/gitbucket/core/util/CsrfUtilSpec.scala` - Comprehensive tests

### Modified Files
- `src/main/scala/gitbucket/core/controller/ControllerBase.scala` - Enhanced Context with CSRF support
- `src/main/scala/gitbucket/core/controller/AccountController.scala` - Added CSRF protection trait, secured routes
- `src/main/twirl/gitbucket/core/account/ssh.scala.html` - Added CSRF tokens, secure delete forms

## Security Best Practices Applied

1. **Secure by default** - CSRF protection enabled automatically
2. **Fail securely** - Invalid tokens result in clear error messages
3. **Defense in depth** - Multiple layers of protection
4. **Principle of least privilege** - Tokens are session-scoped and time-limited
5. **Security logging** - Comprehensive audit trail for incident response
6. **Input validation** - Added client-side and server-side validation
7. **Secure coding** - Constant-time comparisons prevent side-channel attacks

## Next Steps for Production

1. **Deploy with monitoring** - Monitor CSRF validation logs for attack attempts
2. **User communication** - Notify users about improved security
3. **Security audit** - Review other forms in the application for similar issues
4. **Training** - Educate development team on CSRF prevention patterns

This fix comprehensively addresses the CSRF vulnerability while maintaining usability and providing a foundation for secure form handling throughout the GitBucket application.