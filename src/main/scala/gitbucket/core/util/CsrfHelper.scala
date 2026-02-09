package gitbucket.core.util

import javax.servlet.http.HttpServletRequest
import play.twirl.api.Html
import java.security.SecureRandom
import java.util.Base64

/**
 * CSRF helper functions for Twirl templates.
 * 
 * These generate Html objects directly, which are automatically
 * escaped properly by Twirl.
 */
object CsrfHelper {
  
  private val CsrfTokenKey = "_csrf_token"
  private val TokenLength = 32
  private val secureRandom = new SecureRandom()
  
  /**
   * Gets or generates a CSRF token for the current session.
   */
  def getToken(implicit request: HttpServletRequest): String = {
    val session = request.getSession(true)
    Option(session.getAttribute(CsrfTokenKey).asInstanceOf[String]).getOrElse {
      val bytes = new Array[Byte](TokenLength)
      secureRandom.nextBytes(bytes)
      val token = Base64.getUrlEncoder.withoutPadding().encodeToString(bytes)
      session.setAttribute(CsrfTokenKey, token)
      token
    }
  }
  
  /**
   * Generates a hidden input field for forms.
   * Returns Html type for safe Twirl interpolation.
   */
  def tokenField(implicit request: HttpServletRequest): Html = {
    Html(s"""<input type="hidden" name="_csrf_token" value="${getToken}" />""")
  }
  
  /**
   * Generates a meta tag for JavaScript AJAX requests.
   */
  def metaTag(implicit request: HttpServletRequest): Html = {
    Html(s"""<meta name="csrf-token" content="${getToken}" />""")
  }
  
  /**
   * Returns just the token value (already escaped for attribute use).
   * Useful for data attributes or JavaScript initialization.
   */
  def tokenValue(implicit request: HttpServletRequest): String = {
    // HTML-escape the token for safe attribute embedding
    getToken.replace("&", "&amp;")
           .replace("<", "&lt;")
           .replace(">", "&gt;")
           .replace("\"", "&quot;")
           .replace("'", "&#x27;")
  }
}