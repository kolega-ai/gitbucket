package gitbucket.core.util

import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.mockito.MockitoSugar
import org.mockito.Mockito._
import javax.servlet.http.{HttpServletRequest, HttpSession}

class CsrfUtilSpec extends AnyFunSpec with Matchers with MockitoSugar {
  
  describe("CsrfUtil") {
    
    describe("generateToken") {
      it("should generate tokens of correct length") {
        val token = CsrfUtil.generateToken()
        // Base64 encoded 32 bytes without padding = ~43 characters
        token.length should be >= 40
        token.length should be <= 45
      }
      
      it("should generate unique tokens") {
        val tokens = (1 to 100).map(_ => CsrfUtil.generateToken())
        tokens.distinct.length shouldBe 100
      }
      
      it("should generate URL-safe tokens") {
        val token = CsrfUtil.generateToken()
        // URL-safe base64 should not contain +, /, or =
        token should not include "+"
        token should not include "/"
        token should not include "="
      }
      
      it("should generate tokens that are not empty") {
        val token = CsrfUtil.generateToken()
        token should not be empty
      }
    }
    
    describe("getOrCreateToken") {
      it("should return existing token from session") {
        val session = mock[HttpSession]
        val existingToken = "existing-token"
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(existingToken)
        
        val result = CsrfUtil.getOrCreateToken(session)
        result shouldBe existingToken
        verify(session, never()).setAttribute(any(), any())
      }
      
      it("should create new token when none exists") {
        val session = mock[HttpSession]
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)
        
        val result = CsrfUtil.getOrCreateToken(session)
        result should not be empty
        verify(session).setAttribute("gitbucket.csrf.token", result)
      }
    }
    
    describe("validateToken") {
      it("should return false when session is null") {
        val request = mock[HttpServletRequest]
        when(request.getSession(false)).thenReturn(null)
        
        CsrfUtil.validateToken(request) shouldBe false
      }
      
      it("should return false when no token in session") {
        val request = mock[HttpServletRequest]
        val session = mock[HttpSession]
        when(request.getSession(false)).thenReturn(session)
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(null)
        when(request.getParameter("csrf_token")).thenReturn(null)
        when(request.getHeader("X-CSRF-Token")).thenReturn(null)
        
        CsrfUtil.validateToken(request) shouldBe false
      }
      
      it("should return false when tokens don't match") {
        val request = mock[HttpServletRequest]
        val session = mock[HttpSession]
        when(request.getSession(false)).thenReturn(session)
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn("token-a")
        when(request.getParameter("csrf_token")).thenReturn("token-b")
        when(request.getHeader("X-CSRF-Token")).thenReturn(null)
        
        CsrfUtil.validateToken(request) shouldBe false
      }
      
      it("should return true when tokens match from parameter") {
        val request = mock[HttpServletRequest]
        val session = mock[HttpSession]
        val token = CsrfUtil.generateToken()
        when(request.getSession(false)).thenReturn(session)
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(token)
        when(request.getParameter("csrf_token")).thenReturn(token)
        when(request.getHeader("X-CSRF-Token")).thenReturn(null)
        
        CsrfUtil.validateToken(request) shouldBe true
      }
      
      it("should return true when tokens match from header") {
        val request = mock[HttpServletRequest]
        val session = mock[HttpSession]
        val token = CsrfUtil.generateToken()
        when(request.getSession(false)).thenReturn(session)
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(token)
        when(request.getParameter("csrf_token")).thenReturn(null)
        when(request.getHeader("X-CSRF-Token")).thenReturn(token)
        
        CsrfUtil.validateToken(request) shouldBe true
      }
      
      it("should return false for empty token parameter") {
        val request = mock[HttpServletRequest]
        val session = mock[HttpSession]
        val token = CsrfUtil.generateToken()
        when(request.getSession(false)).thenReturn(session)
        when(session.getAttribute("gitbucket.csrf.token")).thenReturn(token)
        when(request.getParameter("csrf_token")).thenReturn("")
        when(request.getHeader("X-CSRF-Token")).thenReturn(null)
        
        CsrfUtil.validateToken(request) shouldBe false
      }
    }
    
    describe("token constants") {
      it("should provide correct token parameter name") {
        CsrfUtil.tokenParameterName shouldBe "csrf_token"
      }
      
      it("should provide correct token header name") {
        CsrfUtil.tokenHeaderName shouldBe "X-CSRF-Token"
      }
    }
  }
}