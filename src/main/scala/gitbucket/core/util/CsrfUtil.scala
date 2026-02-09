package gitbucket.core.util

import java.security.SecureRandom
import java.util.Base64
import javax.servlet.http.{HttpServletRequest, HttpSession}

/**
 * CSRF (Cross-Site Request Forgery) protection utilities
 * 
 * Provides secure token generation, storage, and validation to protect against CSRF attacks.
 * Implements constant-time string comparison to prevent timing attacks.
 */
object CsrfUtil {
  private val TokenLength = 32
  private val TokenSessionKey = "gitbucket.csrf.token"
  private val TokenParameterName = "csrf_token"
  private val TokenHeaderName = "X-CSRF-Token"
  
  private val secureRandom = new SecureRandom()
  
  /**
   * Generate a cryptographically secure CSRF token
   */
  def generateToken(): String = {
    val bytes = new Array[Byte](TokenLength)
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
  }
  
  /**
   * Get existing token from session or create a new one
   * 
   * @param session HTTP session
   * @return CSRF token
   */
  def getOrCreateToken(session: HttpSession): String = {
    Option(session.getAttribute(TokenSessionKey).asInstanceOf[String])
      .getOrElse {
        val token = generateToken()
        session.setAttribute(TokenSessionKey, token)
        token
      }
  }
  
  /**
   * Validate CSRF token from request against session token
   * Uses constant-time comparison to prevent timing attacks
   * 
   * @param request HTTP request containing the token
   * @return true if token is valid
   */
  def validateToken(request: HttpServletRequest): Boolean = {
    val session = request.getSession(false)
    if (session == null) return false
    
    val sessionToken = Option(session.getAttribute(TokenSessionKey).asInstanceOf[String])
    val requestToken = getTokenFromRequest(request)
    
    (sessionToken, requestToken) match {
      case (Some(expected), Some(actual)) => constantTimeEquals(expected, actual)
      case _ => false
    }
  }
  
  /**
   * Extract CSRF token from request (form parameter or header)
   */
  private def getTokenFromRequest(request: HttpServletRequest): Option[String] = {
    Option(request.getParameter(TokenParameterName))
      .orElse(Option(request.getHeader(TokenHeaderName)))
      .filter(_.nonEmpty)
  }
  
  /**
   * Constant-time string comparison to prevent timing attacks
   */
  private def constantTimeEquals(a: String, b: String): Boolean = {
    if (a.length != b.length) return false
    
    var result = 0
    for (i <- a.indices) {
      result |= a.charAt(i) ^ b.charAt(i)
    }
    result == 0
  }
  
  def tokenParameterName: String = TokenParameterName
  def tokenHeaderName: String = TokenHeaderName
}