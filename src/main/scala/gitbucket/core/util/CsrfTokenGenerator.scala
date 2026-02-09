package gitbucket.core.util

import java.security.SecureRandom

/**
 * Cryptographically secure CSRF token generator.
 * 
 * Generates 32 bytes (256 bits) of random data, hex-encoded to 64 characters.
 * This provides sufficient entropy to prevent brute-force attacks.
 */
object CsrfTokenGenerator {
  
  // Thread-local SecureRandom for thread safety without contention
  private val secureRandom: ThreadLocal[SecureRandom] = ThreadLocal.withInitial(() => {
    // Use strong instance when available, fall back to default
    try {
      SecureRandom.getInstanceStrong()
    } catch {
      case _: Exception => new SecureRandom()
    }
  })
  
  private val TokenLengthBytes = 32
  
  /**
   * Generates a new cryptographically secure CSRF token.
   * 
   * @return 64-character hex-encoded token string
   */
  def generateToken(): String = {
    val bytes = new Array[Byte](TokenLengthBytes)
    secureRandom.get().nextBytes(bytes)
    bytesToHex(bytes)
  }
  
  private def bytesToHex(bytes: Array[Byte]): String = {
    bytes.map(b => f"${b & 0xff}%02x").mkString
  }
  
  /**
   * Validates token format without checking against stored value.
   * Useful for early rejection of malformed tokens.
   */
  def isValidTokenFormat(token: String): Boolean = {
    token != null && 
    token.length == TokenLengthBytes * 2 &&
    token.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
  }
}