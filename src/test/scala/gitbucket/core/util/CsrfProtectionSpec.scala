package gitbucket.core.util

import org.scalatest.funspec.AnyFunSpec
import org.mockito.Mockito._
import org.mockito.ArgumentMatchers._
import org.scalatestplus.mockito.MockitoSugar
import javax.servlet.http.HttpSession

class CsrfProtectionSpec extends AnyFunSpec with MockitoSugar {

  describe("getOrCreateToken") {
    it("should generate new token for new session") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)

      val token = CsrfProtection.getOrCreateToken(session)

      assert(token != null)
      assert(token.nonEmpty)
      assert(token.length >= 32)
      verify(session).setAttribute(eq("gitbucket.csrf.token"), anyString())
    }

    it("should return existing token for existing session") {
      val session = mock[HttpSession]
      val existingToken = "existing-token-123"
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(existingToken)

      val token = CsrfProtection.getOrCreateToken(session)

      assert(token == existingToken)
      verify(session, never()).setAttribute(anyString(), anyString())
    }

    it("should generate different tokens for different calls") {
      val session1 = mock[HttpSession]
      val session2 = mock[HttpSession]
      when(session1.getAttribute("gitbucket.csrf.token")).thenReturn(null)
      when(session2.getAttribute("gitbucket.csrf.token")).thenReturn(null)

      val token1 = CsrfProtection.getOrCreateToken(session1)
      val token2 = CsrfProtection.getOrCreateToken(session2)

      assert(token1 != token2)
    }
  }

  describe("validateToken") {
    it("should return true for matching tokens") {
      val session = mock[HttpSession]
      val token = "valid-token-456"
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(token)

      val result = CsrfProtection.validateToken(session, Some(token))

      assert(result == true)
    }

    it("should return false for mismatched tokens") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn("token-a")

      val result = CsrfProtection.validateToken(session, Some("token-b"))

      assert(result == false)
    }

    it("should return false for missing submitted token") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn("valid-token")

      val result = CsrfProtection.validateToken(session, None)

      assert(result == false)
    }

    it("should return false for missing session token") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)

      val result = CsrfProtection.validateToken(session, Some("submitted-token"))

      assert(result == false)
    }

    it("should return false for both tokens being None") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)

      val result = CsrfProtection.validateToken(session, None)

      assert(result == false)
    }
  }

  describe("regenerateToken") {
    it("should generate new token and store in session") {
      val session = mock[HttpSession]

      val token = CsrfProtection.regenerateToken(session)

      assert(token != null)
      assert(token.nonEmpty)
      assert(token.length >= 32)
      verify(session).setAttribute(eq("gitbucket.csrf.token"), eq(token))
    }

    it("should generate different token each time") {
      val session = mock[HttpSession]

      val token1 = CsrfProtection.regenerateToken(session)
      val token2 = CsrfProtection.regenerateToken(session)

      assert(token1 != token2)
      verify(session).setAttribute(eq("gitbucket.csrf.token"), eq(token1))
      verify(session).setAttribute(eq("gitbucket.csrf.token"), eq(token2))
    }
  }

  describe("security properties") {
    it("should generate tokens with sufficient entropy") {
      val session = mock[HttpSession]
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)

      val tokens = (1 to 100).map(_ => CsrfProtection.getOrCreateToken(mock[HttpSession]))
      val uniqueTokens = tokens.toSet

      // All tokens should be unique
      assert(uniqueTokens.size == 100)
      
      // Tokens should be Base64 URL-safe encoded (no padding, URL-safe chars)
      tokens.foreach { token =>
        assert(token.matches("[A-Za-z0-9_-]+"))
        assert(!token.contains("=")) // No padding
      }
    }

    it("should perform constant-time comparison for same-length strings") {
      val session = mock[HttpSession]
      val correctToken = "abcdefghijklmnopqrstuvwxyz123456"
      val wrongToken =   "zbcdefghijklmnopqrstuvwxyz123456"
      
      when(session.getAttribute("gitbucket.csrf.token")).thenReturn(correctToken)

      // Both should take similar time (constant-time comparison)
      // We can't easily test timing, but we can test the functionality
      val result1 = CsrfProtection.validateToken(session, Some(correctToken))
      val result2 = CsrfProtection.validateToken(session, Some(wrongToken))

      assert(result1 == true)
      assert(result2 == false)
    }
  }
}