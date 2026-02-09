package gitbucket.core.util

import liquibase.change.custom.{CustomTaskChange, CustomTaskRollback}
import liquibase.database.Database
import liquibase.database.jvm.JdbcConnection
import liquibase.exception.{CustomChangeException, ValidationErrors}
import liquibase.resource.ResourceAccessor
import org.slf4j.LoggerFactory
import gitbucket.core.util.StringUtil

import java.security.SecureRandom
import java.sql.PreparedStatement

/**
 * Custom Liquibase migration for creating the initial admin account.
 * 
 * Resolves the admin password from (in priority order):
 *   1. GITBUCKET_ADMIN_PASSWORD environment variable
 *   2. gitbucket.admin.password system property  
 *   3. Securely generated random password (logged on first run)
 *
 * This replaces the hardcoded password hash that was previously in the XML
 * migration file (CWE-798 remediation).
 */
class AdminAccountMigration extends CustomTaskChange with CustomTaskRollback {
  
  private val logger = LoggerFactory.getLogger(classOf[AdminAccountMigration])
  
  // Configuration constants
  private val ENV_VAR_NAME = "GITBUCKET_ADMIN_PASSWORD"
  private val SYS_PROP_NAME = "gitbucket.admin.password"
  private val ADMIN_USERNAME = "root"
  private val RANDOM_PASSWORD_LENGTH = 16
  private val RANDOM_PASSWORD_CHARS = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
  
  override def execute(database: Database): Unit = {
    val connection = database.getConnection.asInstanceOf[JdbcConnection]
    val jdbcConnection = connection.getUnderlyingConnection
    
    // Check if admin account already exists (idempotency)
    val checkStmt = jdbcConnection.prepareStatement(
      "SELECT COUNT(*) FROM ACCOUNT WHERE USER_NAME = ?"
    )
    try {
      checkStmt.setString(1, ADMIN_USERNAME)
      val rs = checkStmt.executeQuery()
      rs.next()
      if (rs.getInt(1) > 0) {
        logger.info("Admin account already exists, skipping creation")
        return
      }
    } finally {
      checkStmt.close()
    }
    
    // Resolve password with clear priority chain
    val (password, source) = resolvePassword()
    
    // Generate PBKDF2 hash (using existing GitBucket utility)
    val passwordHash = StringUtil.pbkdf2_sha256(password)
    
    // Insert admin account
    val insertStmt = jdbcConnection.prepareStatement(
      """INSERT INTO ACCOUNT (
        USER_NAME, MAIL_ADDRESS, PASSWORD, ADMINISTRATOR, URL, 
        REGISTERED_DATE, UPDATED_DATE, LAST_LOGIN_DATE, IMAGE,
        GROUP_ACCOUNT, FULL_NAME, REMOVED
      ) VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 
                NULL, NULL, FALSE, ?, FALSE)"""
    )
    
    try {
      insertStmt.setString(1, ADMIN_USERNAME)
      insertStmt.setString(2, s"$ADMIN_USERNAME@localhost")
      insertStmt.setString(3, passwordHash)
      insertStmt.setBoolean(4, true)  // ADMINISTRATOR = true
      insertStmt.setString(5, "https://github.com/gitbucket/gitbucket")
      insertStmt.setString(6, ADMIN_USERNAME)
      insertStmt.executeUpdate()
      
      // Log based on source (never log the actual password from env/prop)
      source match {
        case "generated" =>
          logger.warn("=" * 70)
          logger.warn("GITBUCKET INITIAL SETUP")
          logger.warn("=" * 70)
          logger.warn(s"Generated admin password: $password")
          logger.warn(s"Username: $ADMIN_USERNAME")
          logger.warn("")
          logger.warn("IMPORTANT: Change this password immediately after first login!")
          logger.warn("This password will NOT be shown again.")
          logger.warn("")
          logger.warn("To set a specific password, use environment variable:")
          logger.warn(s"  $ENV_VAR_NAME=yourpassword")
          logger.warn("=" * 70)
          
        case _ =>
          logger.info(s"Admin account created with password from $source")
          logger.info(s"Username: $ADMIN_USERNAME")
      }
      
    } finally {
      insertStmt.close()
    }
  }
  
  /**
   * Resolves the admin password from configuration sources.
   * Returns (password, source) tuple for logging purposes.
   */
  private def resolvePassword(): (String, String) = {
    // Priority 1: Environment variable
    Option(System.getenv(ENV_VAR_NAME))
      .filter(_.nonEmpty)
      .map(p => (p, s"environment variable $ENV_VAR_NAME"))
      .getOrElse {
        // Priority 2: System property
        Option(System.getProperty(SYS_PROP_NAME))
          .filter(_.nonEmpty)
          .map(p => (p, s"system property $SYS_PROP_NAME"))
          .getOrElse {
            // Priority 3: Generate secure random
            (generateSecurePassword(), "generated")
          }
      }
  }
  
  /**
   * Generates a cryptographically secure random password.
   */
  private def generateSecurePassword(): String = {
    val random = new SecureRandom()
    val password = new StringBuilder(RANDOM_PASSWORD_LENGTH)
    
    for (_ <- 0 until RANDOM_PASSWORD_LENGTH) {
      val index = random.nextInt(RANDOM_PASSWORD_CHARS.length)
      password.append(RANDOM_PASSWORD_CHARS.charAt(index))
    }
    
    password.toString()
  }
  
  override def rollback(database: Database): Unit = {
    val connection = database.getConnection.asInstanceOf[JdbcConnection]
    val jdbcConnection = connection.getUnderlyingConnection
    
    val stmt = jdbcConnection.prepareStatement(
      "DELETE FROM ACCOUNT WHERE USER_NAME = ?"
    )
    try {
      stmt.setString(1, ADMIN_USERNAME)
      stmt.executeUpdate()
      logger.info(s"Rolled back admin account creation for user: $ADMIN_USERNAME")
    } finally {
      stmt.close()
    }
  }
  
  override def getConfirmationMessage: String = 
    "Admin account created successfully with secure password handling"
  
  override def setUp(): Unit = {}
  
  override def setFileOpener(resourceAccessor: ResourceAccessor): Unit = {}
  
  override def validate(database: Database): ValidationErrors = 
    new ValidationErrors()
}