package gitbucket.core.controller

import gitbucket.core.util.CsrfUtil
import org.scalatra.{ActionResult, ScalatraBase, Forbidden}
import org.slf4j.LoggerFactory

/**
 * Trait providing CSRF protection for Scalatra controllers
 * 
 * This trait can be mixed into controllers to automatically validate CSRF tokens
 * on state-changing requests (POST, PUT, DELETE, PATCH).
 */
trait CsrfProtection extends ScalatraBase {
  
  private val logger = LoggerFactory.getLogger(classOf[CsrfProtection])
  
  /**
   * HTTP methods that modify state and require CSRF protection
   */
  protected val csrfProtectedMethods: Set[String] = Set("POST", "PUT", "DELETE", "PATCH")
  
  /**
   * Paths that should be excluded from CSRF checks (e.g., API endpoints with other auth)
   * Override this method in subclasses to customize excluded paths
   */
  protected def csrfExcludedPaths: Seq[String] = Seq("/api/")
  
  /**
   * Before filter to validate CSRF tokens on state-changing requests
   * This runs before every action in controllers that mix in this trait
   */
  before() {
    if (requiresCsrfValidation && !isValidCsrfToken) {
      logger.warn(s"CSRF validation failed for ${request.getMethod} ${request.getRequestURI} " +
        s"from ${request.getRemoteAddr} - User-Agent: ${Option(request.getHeader("User-Agent")).getOrElse("unknown")}")
      halt(403, "CSRF token validation failed")
    }
  }
  
  /**
   * Check if current request requires CSRF validation
   */
  private def requiresCsrfValidation: Boolean = {
    csrfProtectedMethods.contains(request.getMethod.toUpperCase) &&
      !isExcludedPath &&
      !isApiRequestWithAuth
  }
  
  /**
   * Check if the current path is excluded from CSRF validation
   */
  private def isExcludedPath: Boolean = {
    val path = request.getRequestURI
    csrfExcludedPaths.exists(excluded => path.startsWith(excluded))
  }
  
  /**
   * Check if request is an API request with token-based authentication
   * API requests typically use Authorization headers instead of cookie-based sessions
   */
  private def isApiRequestWithAuth: Boolean = {
    request.getRequestURI.startsWith("/api/") &&
      Option(request.getHeader("Authorization")).isDefined
  }
  
  /**
   * Validate the CSRF token from the request
   */
  private def isValidCsrfToken: Boolean = {
    CsrfUtil.validateToken(request)
  }
}

/**
 * Alternative trait for controllers that want selective CSRF protection
 * instead of automatic protection on all routes
 */
trait SelectiveCsrfProtection extends ScalatraBase {
  
  private val logger = LoggerFactory.getLogger(classOf[SelectiveCsrfProtection])
  
  /**
   * Wrapper to require CSRF validation for specific actions
   * Use this to protect individual routes rather than all routes
   * 
   * Example usage:
   * post("/sensitive-action") {
   *   withCsrfProtection {
   *     // your action code here
   *   }
   * }
   */
  protected def withCsrfProtection[T](action: => T): T = {
    if (!CsrfUtil.validateToken(request)) {
      logger.warn(s"CSRF validation failed for ${request.getMethod} ${request.getRequestURI} " +
        s"from ${request.getRemoteAddr}")
      halt(403, "CSRF token validation failed")
    }
    action
  }
}