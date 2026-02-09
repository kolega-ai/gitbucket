package gitbucket.core.util

import org.scalatra.{ScalatraBase, ActionResult, Forbidden}
import java.security.SecureRandom
import java.util.Base64
import javax.servlet.http.HttpServletRequest

/**
 * CSRF Protection for Scalatra applications.
 * 
 * Implements the Synchronizer Token Pattern:
 * - Generates cryptographically secure tokens
 * - Stores tokens in server-side session
 * - Validates tokens on state-changing requests
 * 
 * Usage:
 *   class MyServlet extends ScalatraServlet with CsrfProtection {
 *     csrfGuard() // Install protection
 *     
 *     post("/submit") {
 *       // Token already validated by before filter
 *       ...
 *     }
 *   }
 */
trait CsrfProtection extends ScalatraBase {
  
  // ============================================================
  // Configuration
  // ============================================================
  
  /** Session key for storing the CSRF token */
  protected val CsrfTokenKey: String = "_csrf_token"
  
  /** Parameter name for form submissions */
  protected val CsrfTokenParam: String = "_csrf_token"
  
  /** Header name for AJAX requests */
  protected val CsrfTokenHeader: String = "X-CSRF-Token"
  
  /** Token length in bytes (32 bytes = 256 bits of entropy) */
  protected val TokenLength: Int = 32
  
  /** HTTP methods that require CSRF validation */
  protected val ProtectedMethods: Set[String] = Set("POST", "PUT", "DELETE", "PATCH")
  
  /** Paths to exclude from CSRF protection (e.g., API endpoints with their own auth) */
  protected def csrfExcludedPaths: Set[String] = Set.empty
  
  // ============================================================
  // Token Generation
  // ============================================================
  
  /** Thread-safe secure random instance */
  private val secureRandom = new SecureRandom()
  
  /**
   * Generates a cryptographically secure random token.
   * Uses Base64 URL-safe encoding for compatibility with forms and headers.
   */
  protected def generateToken(): String = {
    val bytes = new Array[Byte](TokenLength)
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }
  
  /**
   * Gets the current CSRF token from session, generating one if needed.
   * This is the primary method templates should use.
   */
  def csrfToken(implicit request: HttpServletRequest): String = {
    val session = request.getSession(true)
    Option(session.getAttribute(CsrfTokenKey).asInstanceOf[String]).getOrElse {
      val token = generateToken()
      session.setAttribute(CsrfTokenKey, token)
      token
    }
  }
  
  /**
   * Regenerates the CSRF token. Call this after login to prevent
   * session fixation attacks that could expose the token.
   */
  def regenerateCsrfToken(implicit request: HttpServletRequest): String = {
    val session = request.getSession(true)
    val token = generateToken()
    session.setAttribute(CsrfTokenKey, token)
    token
  }
  
  // ============================================================
  // Token Validation
  // ============================================================
  
  /**
   * Extracts the submitted CSRF token from the request.
   * Checks both form parameter and custom header (for AJAX).
   */
  protected def extractSubmittedToken(implicit request: HttpServletRequest): Option[String] = {
    // First check the request parameter (form submission)
    Option(request.getParameter(CsrfTokenParam))
      // Then check the custom header (AJAX)
      .orElse(Option(request.getHeader(CsrfTokenHeader)))
      // Filter out empty strings
      .filter(_.nonEmpty)
  }
  
  /**
   * Gets the expected token from the session.
   */
  protected def getSessionToken(implicit request: HttpServletRequest): Option[String] = {
    Option(request.getSession(false))
      .flatMap(s => Option(s.getAttribute(CsrfTokenKey).asInstanceOf[String]))
  }
  
  /**
   * Validates the CSRF token using constant-time comparison
   * to prevent timing attacks.
   */
  protected def validateCsrfToken(implicit request: HttpServletRequest): Boolean = {
    val submitted = extractSubmittedToken
    val expected = getSessionToken
    
    (submitted, expected) match {
      case (Some(s), Some(e)) => constantTimeEquals(s, e)
      case _ => false
    }
  }
  
  /**
   * Constant-time string comparison to prevent timing attacks.
   * Always compares all bytes regardless of where a mismatch occurs.
   */
  private def constantTimeEquals(a: String, b: String): Boolean = {
    if (a.length != b.length) {
      // Still do a comparison to maintain constant time
      val dummy = "x" * a.length
      dummy.zip(a).foldLeft(0)((acc, pair) => acc | (pair._1 ^ pair._2))
      false
    } else {
      a.zip(b).foldLeft(0)((acc, pair) => acc | (pair._1 ^ pair._2)) == 0
    }
  }
  
  /**
   * Checks if the current request path is excluded from CSRF protection.
   */
  protected def isExcludedPath(implicit request: HttpServletRequest): Boolean = {
    val path = request.getRequestURI
    csrfExcludedPaths.exists(excluded => path.startsWith(excluded))
  }
  
  /**
   * Checks if the current request method requires CSRF protection.
   */
  protected def requiresCsrfProtection(implicit request: HttpServletRequest): Boolean = {
    ProtectedMethods.contains(request.getMethod.toUpperCase)
  }
  
  // ============================================================
  // Before Filter Integration
  // ============================================================
  
  /**
   * Installs the CSRF validation filter.
   * Call this in your servlet's initialize block or mix it in.
   */
  protected def csrfGuard(): Unit = {
    before() {
      implicit val req = request
      if (requiresCsrfProtection && !isExcludedPath) {
        if (!validateCsrfToken) {
          halt(403, "CSRF token validation failed")
        }
      }
    }
  }
  
  /**
   * Alternative: Manual validation method for use in specific routes.
   * Returns an ActionResult on failure for flexible error handling.
   */
  protected def requireValidCsrfToken()(implicit request: HttpServletRequest): Option[ActionResult] = {
    if (!validateCsrfToken) {
      Some(Forbidden("Invalid or missing CSRF token"))
    } else {
      None
    }
  }
  
  // ============================================================
  // Template Helpers
  // ============================================================
  
  /**
   * Generates a hidden input field containing the CSRF token.
   * Use this in Twirl templates: @csrfTokenField
   */
  def csrfTokenField(implicit request: HttpServletRequest): String = {
    s"""<input type="hidden" name="$CsrfTokenParam" value="${csrfToken}" />"""
  }
  
  /**
   * Generates a meta tag for JavaScript to read.
   * Use this in layouts for AJAX requests.
   */
  def csrfMetaTag(implicit request: HttpServletRequest): String = {
    s"""<meta name="csrf-token" content="${csrfToken}" />"""
  }
}