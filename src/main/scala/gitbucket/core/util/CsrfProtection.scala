package gitbucket.core.util

import javax.servlet.http.HttpSession
import java.security.SecureRandom
import java.util.Base64

/**
 * CSRF protection utility using the synchronizer token pattern.
 * Implements secure token generation, validation, and management.
 */
object CsrfProtection {
  
  private val CSRF_TOKEN_KEY = "gitbucket.csrf.token"
  private val TOKEN_LENGTH = 32
  private val secureRandom = new SecureRandom()
  
  /**
   * Generates or retrieves existing CSRF token for the session.
   * Uses synchronizer token pattern - one token per session.
   */
  def getOrCreateToken(session: HttpSession): String = {
    Option(session.getAttribute(CSRF_TOKEN_KEY).asInstanceOf[String]) match {
      case Some(token) => token
      case None =>
        val token = generateToken()
        session.setAttribute(CSRF_TOKEN_KEY, token)
        token
    }
  }
  
  /**
   * Validates the submitted CSRF token against session token.
   * Uses constant-time comparison to prevent timing attacks.
   */
  def validateToken(session: HttpSession, submittedToken: Option[String]): Boolean = {
    val sessionToken = Option(session.getAttribute(CSRF_TOKEN_KEY).asInstanceOf[String])
    
    (sessionToken, submittedToken) match {
      case (Some(expected), Some(actual)) => constantTimeEquals(expected, actual)
      case _ => false
    }
  }
  
  /**
   * Regenerates the CSRF token. Call after sensitive operations
   * to prevent token fixation attacks.
   */
  def regenerateToken(session: HttpSession): String = {
    val token = generateToken()
    session.setAttribute(CSRF_TOKEN_KEY, token)
    token
  }
  
  private def generateToken(): String = {
    val bytes = new Array[Byte](TOKEN_LENGTH)
    secureRandom.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
  }
  
  /**
   * Constant-time string comparison to prevent timing attacks.
   */
  private def constantTimeEquals(a: String, b: String): Boolean = {
    if (a.length != b.length) {
      // Still do comparison to maintain constant time
      val dummy = a
      dummy.zip(dummy).foldLeft(0)((acc, pair) => acc | (pair._1 ^ pair._2))
      false
    } else {
      val result = a.zip(b).foldLeft(0)((acc, pair) => acc | (pair._1 ^ pair._2))
      result == 0
    }
  }
}