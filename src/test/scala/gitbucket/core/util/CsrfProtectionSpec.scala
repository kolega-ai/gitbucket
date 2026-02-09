package gitbucket.core.util

import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.scalatra.test.scalatest.ScalatraFunSuite
import org.scalatra.ScalatraServlet
import javax.servlet.http.HttpServletRequest

class CsrfProtectionSpec extends ScalatraFunSuite with Matchers {
  
  // Test servlet that uses CSRF protection
  class TestServlet extends ScalatraServlet with CsrfProtection {
    csrfGuard()
    
    get("/form") {
      // Simulate rendering a form with CSRF token
      s"""<form><input name="_csrf_token" value="${csrfToken}" /></form>"""
    }
    
    get("/token") {
      csrfToken
    }
    
    post("/submit") {
      "Success"
    }
    
    // Endpoint that bypasses CSRF for testing
    override def csrfExcludedPaths: Set[String] = Set("/api/")
    
    post("/api/webhook") {
      "Webhook received"
    }
  }
  
  addServlet(new TestServlet, "/*")
  
  // ============================================================
  // Token Generation Tests
  // ============================================================
  
  test("GET request should not require CSRF token") {
    get("/form") {
      status should equal(200)
      body should include("_csrf_token")
    }
  }
  
  test("Should generate consistent token within session") {
    session {
      var token1 = ""
      var token2 = ""
      
      get("/token") {
        status should equal(200)
        token1 = body
      }
      
      get("/token") {
        status should equal(200)
        token2 = body
      }
      
      token1 should equal(token2)
      token1 should not be empty
    }
  }
  
  test("Different sessions should have different tokens") {
    var token1 = ""
    var token2 = ""
    
    session {
      get("/token") {
        token1 = body
      }
    }
    
    session {
      get("/token") {
        token2 = body
      }
    }
    
    token1 should not equal token2
  }
  
  // ============================================================
  // Token Validation Tests
  // ============================================================
  
  test("POST without CSRF token should fail with 403") {
    session {
      post("/submit") {
        status should equal(403)
        body should include("CSRF")
      }
    }
  }
  
  test("POST with invalid CSRF token should fail with 403") {
    session {
      post("/submit", "_csrf_token" -> "invalid-token") {
        status should equal(403)
      }
    }
  }
  
  test("POST with valid CSRF token should succeed") {
    session {
      var token = ""
      
      get("/token") {
        token = body
      }
      
      post("/submit", "_csrf_token" -> token) {
        status should equal(200)
        body should equal("Success")
      }
    }
  }
  
  test("POST with CSRF token in header should succeed") {
    session {
      var token = ""
      
      get("/token") {
        token = body
      }
      
      post("/submit", headers = Map("X-CSRF-Token" -> token)) {
        status should equal(200)
        body should equal("Success")
      }
    }
  }
  
  // ============================================================
  // Exclusion Tests
  // ============================================================
  
  test("Excluded paths should not require CSRF token") {
    post("/api/webhook") {
      status should equal(200)
      body should equal("Webhook received")
    }
  }
  
  // ============================================================
  // Security Tests
  // ============================================================
  
  test("Token should have sufficient entropy") {
    session {
      get("/token") {
        // Base64 of 32 bytes = ~43 characters
        body.length should be >= 40
      }
    }
  }
  
  test("Tokens should appear random") {
    val tokens = (1 to 10).map { _ =>
      var token = ""
      session {
        get("/token") {
          token = body
        }
      }
      token
    }
    
    // All tokens should be unique
    tokens.toSet.size should equal(10)
  }
  
  test("Should reject token from different session") {
    var stolenToken = ""
    
    // Attacker's session
    session {
      get("/token") {
        stolenToken = body
      }
    }
    
    // Victim's session - attacker tries to use their token
    session {
      post("/submit", "_csrf_token" -> stolenToken) {
        status should equal(403)
      }
    }
  }
}