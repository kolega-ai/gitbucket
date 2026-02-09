# CSRF Protection in GitBucket

This document describes the Cross-Site Request Forgery (CSRF) protection implementation in GitBucket.

## Overview

CSRF protection prevents malicious websites from making unauthorized requests on behalf of authenticated users. GitBucket implements the **synchronizer token pattern** to protect against CSRF attacks.

## Implementation

### Core Components

1. **CsrfProtection Utility** (`src/main/scala/gitbucket/core/util/CsrfProtection.scala`)
   - Generates cryptographically secure CSRF tokens
   - Validates tokens using constant-time comparison
   - Manages token lifecycle in user sessions

2. **CsrfProtectionSupport Trait** (`src/main/scala/gitbucket/core/controller/CsrfProtectionSupport.scala`)
   - Provides CSRF protection methods for controllers
   - Can be mixed into any controller that needs protection

3. **Template Helper** (`src/main/twirl/gitbucket/core/helper/csrf.scala.html`)
   - Simplifies inclusion of CSRF tokens in forms

### Security Features

- **256-bit entropy**: Tokens are generated using SecureRandom with 32 bytes of randomness
- **Base64 URL-safe encoding**: Tokens are safe for use in URLs and forms
- **Constant-time validation**: Prevents timing attacks during token comparison
- **Session-scoped tokens**: One token per session (synchronizer token pattern)
- **Token regeneration**: Tokens are refreshed after sensitive operations

### Usage

#### In Controllers

```scala
class MyController extends ControllerBase with CsrfProtectionSupport {
  
  get("/form") {
    html.myform(csrfToken)
  }
  
  post("/submit") {
    csrfProtected {
      // Your protected action here
      doSomething()
      // Regenerate token after sensitive operation
      regenerateCsrfToken()
    }
  }
}
```

#### In Templates

```html
<form method="POST" action="/submit">
  <!-- Include CSRF token -->
  <input type="hidden" name="csrf_token" value="@csrfToken" />
  
  <!-- Or use the helper -->
  @gitbucket.core.helper.csrf(csrfToken)
  
  <!-- Rest of your form -->
</form>
```

## Currently Protected Endpoints

- `POST /reset/form` - Password reset form submission

## Security Considerations

### Attack Vectors Mitigated

- ✅ **Cross-site form submission**: Blocked by token validation
- ✅ **Malicious email links**: POST requests require valid tokens
- ✅ **Token prediction**: Cryptographically secure random generation
- ✅ **Timing attacks**: Constant-time token comparison
- ✅ **Session fixation**: Token regeneration after sensitive operations

### Additional Security Measures Needed

- ⚠️ **XSS protection**: Implement Content Security Policy (CSP)
- ⚠️ **Clickjacking**: Add X-Frame-Options header
- ⚠️ **HTTPS enforcement**: Ensure secure token transmission

## Testing

Unit tests are provided in `src/test/scala/gitbucket/core/util/CsrfProtectionSpec.scala` covering:
- Token generation and uniqueness
- Validation logic
- Edge cases and error conditions
- Security properties

## Migration Guide

### Adding CSRF Protection to New Forms

1. Add `CsrfProtectionSupport` trait to your controller
2. Pass `csrfToken` to your template
3. Include hidden CSRF input in your form
4. Wrap POST handler with `csrfProtected { ... }`

### Future: Application-wide Protection

To protect all forms globally:

```scala
trait GlobalCsrfProtection extends CsrfProtectionSupport { 
  self: ScalatraBase =>
  
  private val CSRF_SAFE_METHODS = Set("GET", "HEAD", "OPTIONS")
  private val CSRF_EXEMPT_PATHS = Set("/api/", "/webhook/")
  
  before() {
    if (!CSRF_SAFE_METHODS.contains(request.getMethod) && 
        !CSRF_EXEMPT_PATHS.exists(request.getPathInfo.startsWith)) {
      if (!validateCsrfToken()) {
        halt(403, "CSRF validation failed")
      }
    }
  }
}
```

## References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [Synchronizer Token Pattern](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#synchronizer-token-pattern)