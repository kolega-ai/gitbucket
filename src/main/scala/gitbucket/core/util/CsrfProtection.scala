package gitbucket.core.util

import gitbucket.core.util.CsrfTokenGenerator
import org.scalatra.{ActionResult, ScalatraBase, Forbidden}
import java.security.MessageDigest
import org.slf4j.LoggerFactory

/**
 * CSRF Protection trait for Scalatra controllers.
 * 
 * Provides:
 * - Automatic token generation and session storage
 * - Token validation for state-changing requests
 * - Template helper for including tokens in forms
 * - Support for both form fields and custom headers (AJAX)
 * 
 * Usage:
 * {{{
 *   class MyController extends ControllerBase with CsrfProtection {
 *     post("/sensitive-action") {
 *       validateCsrfToken() {
 *         // Action is protected - token was valid
 *         doSensitiveOperation()
 *       }
 *     }
 *   }
 * }}}
 * 
 * In templates:
 * {{{
 *   <form method="post">
 *     @csrfTokenHiddenField
 *     ...
 *   </form>
 * }}}
 */
trait CsrfProtection { self: ScalatraBase =>
  
  private val logger = LoggerFactory.getLogger(classOf[CsrfProtection])
  
  // Configuration constants
  protected val CsrfSessionKey = "gitbucket.csrf.token"
  protected val CsrfFormFieldName = "_csrf_token"
  protected val CsrfHeaderName = "X-CSRF-Token"
  
  // Allowed origins for additional validation (configure per deployment)
  protected def allowedOrigins: Set[String] = Set.empty
  
  /**
   * Gets the current CSRF token, generating one if not present.
   * This method is idempotent within a session.
   */
  def csrfToken: String = {
    session.get(CsrfSessionKey) match {
      case Some(token: String) if CsrfTokenGenerator.isValidTokenFormat(token) => 
        token
      case _ =>
        val newToken = CsrfTokenGenerator.generateToken()
        session.setAttribute(CsrfSessionKey, newToken)
        logger.debug(s"Generated new CSRF token for session")
        newToken
    }
  }
  
  /**
   * Generates HTML for a hidden form field containing the CSRF token.
   * Use this in Twirl templates.
   */
  def csrfTokenHiddenField: String = {
    s"""<input type="hidden" name="$CsrfFormFieldName" value="$csrfToken" />"""
  }
  
  /**
   * Generates an HTML meta tag for AJAX requests to read the token.
   * Include in page head for JavaScript access.
   */
  def csrfMetaTag: String = {
    s"""<meta name="csrf-token" content="$csrfToken" />"""
  }
  
  /**
   * Validates the CSRF token and executes the action if valid.
   * Returns 403 Forbidden with error message if validation fails.
   * 
   * @param action The action to execute if validation passes
   * @return The action result or 403 Forbidden
   */
  def validateCsrfToken()(action: => Any): Any = {
    extractSubmittedToken() match {
      case None =>
        logger.warn(s"CSRF validation failed: no token submitted for ${request.getRequestURI}")
        csrfValidationFailed("CSRF token missing")
        
      case Some(submittedToken) =>
        session.get(CsrfSessionKey) match {
          case Some(sessionToken: String) if secureCompare(submittedToken, sessionToken) =>
            // Additional defense: validate Origin/Referer if configured
            if (validateOriginHeader()) {
              logger.debug(s"CSRF validation passed for ${request.getRequestURI}")
              action
            } else {
              logger.warn(s"CSRF validation failed: origin mismatch for ${request.getRequestURI}")
              csrfValidationFailed("Invalid request origin")
            }
            
          case Some(_) =>
            logger.warn(s"CSRF validation failed: token mismatch for ${request.getRequestURI}")
            csrfValidationFailed("CSRF token invalid")
            
          case None =>
            logger.warn(s"CSRF validation failed: no session token for ${request.getRequestURI}")
            csrfValidationFailed("Session expired")
        }
    }
  }
  
  /**
   * Extracts the submitted CSRF token from the request.
   * Checks form field first, then custom header (for AJAX).
   */
  protected def extractSubmittedToken(): Option[String] = {
    // Check form field first (standard form submission)
    Option(params.get(CsrfFormFieldName)).flatten
      // Then check custom header (AJAX requests)
      .orElse(Option(request.getHeader(CsrfHeaderName)))
      // Validate format to reject obviously invalid tokens early
      .filter(CsrfTokenGenerator.isValidTokenFormat)
  }
  
  /**
   * Validates Origin/Referer header as defense in depth.
   * Returns true if no allowed origins configured (permissive default).
   */
  protected def validateOriginHeader(): Boolean = {
    if (allowedOrigins.isEmpty) {
      true // Skip validation if not configured
    } else {
      val origin = Option(request.getHeader("Origin"))
        .orElse(Option(request.getHeader("Referer")).map(extractOrigin))
      
      origin match {
        case Some(o) => allowedOrigins.exists(allowed => o.startsWith(allowed))
        case None => false // Require origin header when validation is enabled
      }
    }
  }
  
  /**
   * Extracts origin (scheme + host + port) from a full URL.
   */
  private def extractOrigin(url: String): String = {
    try {
      val uri = new java.net.URI(url)
      val port = if (uri.getPort == -1) "" else s":${uri.getPort}"
      s"${uri.getScheme}://${uri.getHost}$port"
    } catch {
      case _: Exception => ""
    }
  }
  
  /**
   * Constant-time string comparison to prevent timing attacks.
   * Uses MessageDigest.isEqual which is designed for this purpose.
   */
  protected def secureCompare(a: String, b: String): Boolean = {
    if (a == null || b == null) {
      false
    } else {
      MessageDigest.isEqual(a.getBytes("UTF-8"), b.getBytes("UTF-8"))
    }
  }
  
  /**
   * Handles CSRF validation failure.
   * Override this method to customize error response.
   */
  protected def csrfValidationFailed(message: String): ActionResult = {
    Forbidden(
      <html>
        <head><title>403 Forbidden</title></head>
        <body>
          <h1>403 Forbidden</h1>
          <p>CSRF validation failed: {message}</p>
          <p>Please go back, refresh the page, and try again.</p>
        </body>
      </html>
    )
  }
  
  /**
   * Regenerates the CSRF token.
   * Call this after login/logout to prevent session fixation.
   */
  def regenerateCsrfToken(): String = {
    val newToken = CsrfTokenGenerator.generateToken()
    session.setAttribute(CsrfSessionKey, newToken)
    logger.debug("Regenerated CSRF token")
    newToken
  }
}