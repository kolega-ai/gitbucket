package gitbucket.core.controller

import org.scalatra.ScalatraBase
import org.scalatra.ActionResult
import org.scalatra.Forbidden
import gitbucket.core.util.CsrfProtection

/**
 * Trait providing CSRF protection support for controllers.
 * Can be mixed into controllers that need CSRF protection.
 */
trait CsrfProtectionSupport { self: ScalatraBase =>
  
  protected val CSRF_TOKEN_PARAM = "csrf_token"
  
  /**
   * Get CSRF token for use in templates
   */
  protected def csrfToken: String = {
    CsrfProtection.getOrCreateToken(session)
  }
  
  /**
   * Validate CSRF token from request parameters
   * Returns true if valid, false otherwise
   */
  protected def validateCsrfToken(): Boolean = {
    val submittedToken = params.get(CSRF_TOKEN_PARAM)
    CsrfProtection.validateToken(session, submittedToken)
  }
  
  /**
   * Helper to wrap actions with CSRF validation
   */
  protected def csrfProtected(action: => ActionResult): ActionResult = {
    if (validateCsrfToken()) {
      action
    } else {
      Forbidden("Invalid or missing CSRF token")
    }
  }
  
  /**
   * Regenerate token after sensitive operations
   */
  protected def regenerateCsrfToken(): Unit = {
    CsrfProtection.regenerateToken(session)
  }
}