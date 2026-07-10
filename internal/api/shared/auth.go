package shared

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/rivic-q/cryptobom-saas/internal/auth"
	"github.com/sirupsen/logrus"
)

type authRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Edition  string `json:"edition"`
}

type authUserResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

// Auth rate limiter: per-IP, per-endpoint
type authRateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	window   time.Duration
	maxReqs  int
}

func newAuthRateLimiter(maxReqs int, window time.Duration) *authRateLimiter {
	rl := &authRateLimiter{
		attempts: make(map[string][]time.Time),
		window:   window,
		maxReqs:  maxReqs,
	}
	go rl.cleanup()
	return rl
}

func (rl *authRateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-rl.window)
	attempts := rl.attempts[key]
	valid := make([]time.Time, 0, len(attempts))
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) >= rl.maxReqs {
		rl.attempts[key] = valid
		return false
	}
	rl.attempts[key] = append(valid, now)
	return true
}

func (rl *authRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.window)
	for range ticker.C {
		rl.mu.Lock()
		cutoff := time.Now().Add(-rl.window)
		for key, attempts := range rl.attempts {
			valid := make([]time.Time, 0, len(attempts))
			for _, t := range attempts {
				if t.After(cutoff) {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.attempts, key)
			} else {
				rl.attempts[key] = valid
			}
		}
		rl.mu.Unlock()
	}
}

var loginLimiter = newAuthRateLimiter(10, 15*time.Minute) // 10 attempts per 15 min
var registerLimiter = newAuthRateLimiter(5, 1*time.Hour)   // 5 per hour

// SetupAuthRoutes configures shared JWT auth routes.
func SetupAuthRoutes(router *gin.RouterGroup, logger *logrus.Logger, service *auth.AuthService, allowedDomains []string, jwtSecret string) {
	authGroup := router.Group("/auth")
	{
		authGroup.POST("/login", loginHandler(logger, service, allowedDomains))
		authGroup.POST("/register", registerHandler(logger, service, allowedDomains))
		authGroup.POST("/refresh", refreshTokenHandler(service, logger))
		authGroup.POST("/logout", service.JWTAuthMiddleware(nil), logoutHandler(service, logger))
		authGroup.POST("/mfa/verify", mfaVerifyHandler(service, logger))
		authGroup.POST("/mfa/setup", service.JWTAuthMiddleware(nil), mfaSetupHandler(service, logger))
		authGroup.GET("/me", service.JWTAuthMiddleware(nil), meHandler())
		authGroup.GET("/editions", editionsHandler(allowedDomains))

		// Google OAuth
		authGroup.GET("/google/login", GoogleLoginHandler(logger))
		authGroup.Any("/google/callback", GoogleCallbackHandler(logger, service, allowedDomains))
		authGroup.GET("/google/status", GoogleOAuthStatusHandler(logger))

		// GitHub OAuth
		authGroup.GET("/github/login", GitHubLoginHandler(logger))
		authGroup.Any("/github/callback", GitHubCallbackHandler(logger, service, allowedDomains))
		authGroup.GET("/github/status", GitHubOAuthStatusHandler(logger))

		// Demo access
		authGroup.GET("/demo", DemoAccessHandler(logger, jwtSecret))
	}
}

func DemoAccessHandler(logger *logrus.Logger, jwtSecret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		edition := c.DefaultQuery("edition", "oss")
		if edition != "oss" && edition != "enterprise" {
			edition = "oss"
		}

		if jwtSecret == "" {
			jwtSecret = "demo-secret-key-not-for-production"
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"user_id":     "demo-user",
			"tenant_id":   "demo-tenant",
			"email":       "demo@cryptobom.io",
			"name":        "Demo User",
			"role":        "admin",
			"edition":     edition,
			"permissions": []string{"cbom:read", "cbom:write", "cbom:delete", "assets:read", "assets:write", "security:read", "users:manage", "ibmq:attest", "cloud:manage"},
			"sub":         "demo-user",
			"iss":         "cryptobom-saas",
			"iat":         now.Unix(),
			"exp":         now.Add(4 * time.Hour).Unix(),
			"jti":         uuid.New().String(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		accessToken, err := token.SignedString([]byte(jwtSecret))
		if err != nil {
			logger.WithError(err).Error("Failed to generate demo token")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate demo access"})
			return
		}

		refreshClaims := jwt.MapClaims{
			"user_id": "demo-user",
			"sub":     "demo-user",
			"iss":     "cryptobom-saas-refresh",
			"iat":     now.Unix(),
			"exp":     now.Add(72 * time.Hour).Unix(),
			"jti":     uuid.New().String(),
		}
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
		refreshTokenStr, _ := refreshToken.SignedString([]byte(jwtSecret))

		type authUserDisplay struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Email string `json:"email"`
			Role  string `json:"role"`
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshTokenStr,
			"user": authUserDisplay{
				ID:    "demo-user",
				Name:  "Demo User",
				Email: "demo@cryptobom.io",
				Role:  "admin",
			},
			"edition":   edition,
			"demo_mode": true,
		})
	}
}

func loginHandler(logger *logrus.Logger, service *auth.AuthService, allowedDomains []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !loginLimiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many login attempts. Try again later."})
			return
		}

		var req authRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
		if !workEmailAllowed(req.Email, allowedDomains) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Work email domain not allowed"})
			return
		}
		resp, err := service.LoginWithEdition(req.Email, req.Password, req.Edition)
		if err != nil {
			logger.WithError(err).WithField("email", req.Email).Warn("authentication failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
			return
		}

		// MFA required
		if resp.MFARequired {
			c.JSON(http.StatusOK, gin.H{
				"mfa_required": true,
				"mfa_session":  resp.MFASession,
				"message":      "MFA verification required",
			})
			return
		}

		user, err := service.GetUserByEmail(req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to load user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
			"user": authUserResponse{
				ID:    user.ID,
				Name:  user.Name,
				Email: user.Email,
				Role:  user.Role,
			},
			"edition": editionForRole(user.Role, req.Edition),
		})
	}
}

func registerHandler(logger *logrus.Logger, service *auth.AuthService, allowedDomains []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		if !registerLimiter.allow(ip) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many registration attempts. Try again later."})
			return
		}

		var req authRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid JSON"})
			return
		}
		if !workEmailAllowed(req.Email, allowedDomains) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Work email domain not allowed"})
			return
		}
		if strings.TrimSpace(req.Name) == "" {
			req.Name = strings.Split(strings.TrimSpace(req.Email), "@")[0]
		}

		user := &auth.User{
			Email:    strings.ToLower(strings.TrimSpace(req.Email)),
			Name:     strings.TrimSpace(req.Name),
			Password: req.Password,
			Role:     "viewer",
		}

		if err := service.Register(user); err != nil {
			logger.WithError(err).WithField("email", req.Email).Warn("registration failed")
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		resp, err := service.LoginWithEdition(req.Email, req.Password, req.Edition)
		if err != nil {
			logger.WithError(err).WithField("email", req.Email).Warn("registration login failed")
			c.JSON(http.StatusCreated, gin.H{
				"message": "Registration completed. Please log in with your new account.",
				"user":    authUserResponse{Email: user.Email, Name: user.Name, Role: user.Role},
			})
			return
		}

		createdUser, err := service.GetUserByEmail(req.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Unable to load user"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"access_token":  resp.AccessToken,
			"refresh_token": resp.RefreshToken,
			"user": authUserResponse{
				ID:    createdUser.ID,
				Name:  createdUser.Name,
				Email: createdUser.Email,
				Role:  createdUser.Role,
			},
			"edition": editionForRole(createdUser.Role, req.Edition),
		})
	}
}

func meHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"user_id":     c.GetString("user_id"),
			"tenant_id":   c.GetString("tenant_id"),
			"email":       c.GetString("email"),
			"role":        c.GetString("role"),
			"edition":     c.GetString("edition"),
			"permissions": c.GetStringSlice("permissions"),
		})
	}
}

func editionsHandler(allowedDomains []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"editions":     []string{"oss", "enterprise"},
			"work_domains": allowedDomains,
		})
	}
}

func workEmailAllowed(email string, allowedDomains []string) bool {
	if len(allowedDomains) == 0 {
		return true
	}
	parts := strings.Split(strings.ToLower(strings.TrimSpace(email)), "@")
	if len(parts) != 2 {
		return false
	}
	for _, domain := range allowedDomains {
		if parts[1] == strings.ToLower(strings.TrimSpace(domain)) {
			return true
		}
	}
	return false
}

func refreshTokenHandler(service *auth.AuthService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_token required"})
			return
		}
		newAccess, newRefresh, err := service.TokenManager().RefreshAccessToken(req.RefreshToken)
		if err != nil {
			logger.WithError(err).Warn("refresh token failed")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or revoked refresh token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"access_token":  newAccess,
			"refresh_token": newRefresh,
		})
	}
}

func logoutHandler(service *auth.AuthService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
			tokenString := authHeader[7:]
			if err := service.TokenManager().RevokeToken(tokenString); err != nil {
				logger.WithError(err).Warn("logout revocation failed")
			}
		}
		// Clear OAuth cookies
		c.SetCookie("cbom_access_token", "", -1, "/", "", false, true)
		c.SetCookie("cbom_refresh_token", "", -1, "/", "", false, true)
		c.SetCookie("cbom_edition", "", -1, "/", "", false, true)
		c.SetCookie("cbom_user_id", "", -1, "/", "", false, true)
		c.SetCookie("cbom_user_name", "", -1, "/", "", false, true)
		c.SetCookie("cbom_user_email", "", -1, "/", "", false, true)
		c.SetCookie("cbom_user_role", "", -1, "/", "", false, true)
		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

// mfaSetupHandler generates a new TOTP secret and provisioning URI for the user.
func mfaSetupHandler(service *auth.AuthService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString("user_id")
		user, err := service.GetUserByID(userID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "CryptoBOM SaaS",
			AccountName: user.Email,
		})
		if err != nil {
			logger.WithError(err).Error("Failed to generate TOTP key")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate MFA secret"})
			return
		}

		// Store the secret (user must verify before enabling)
		user.MFASecret = key.Secret()
		if err := service.UpdateUser(user); err != nil {
			logger.WithError(err).Error("Failed to store MFA secret")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store MFA secret"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"secret":          key.Secret(),
			"provisioning_uri": key.URL(),
			"message":         "Scan the QR code with your authenticator app, then verify with /auth/mfa/verify",
		})
	}
}

// mfaVerifyHandler verifies a TOTP code and completes login.
func mfaVerifyHandler(service *auth.AuthService, logger *logrus.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req struct {
			MFASession string `json:"mfa_session" binding:"required"`
			MFACode    string `json:"mfa_code" binding:"required"`
			Email      string `json:"email" binding:"required"`
			Edition    string `json:"edition"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		user, err := service.GetUserByEmail(req.Email)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		if !user.MFAEnabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "MFA not enabled for this user"})
			return
		}

		if user.MFASecret == "" {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "MFA secret not configured"})
			return
		}

		// Validate TOTP code against the user's secret
		if !totp.Validate(req.MFACode, user.MFASecret) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid MFA code"})
			return
		}

		edition := req.Edition
		if edition == "" {
			edition = editionForRole(user.Role, req.Edition)
		}

		accessToken, err := service.TokenManager().GenerateToken(user, edition)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}
		refreshToken, err := service.TokenManager().GenerateRefreshToken(user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
			"mfa_verified":  true,
			"user": authUserResponse{
				ID:    user.ID,
				Name:  user.Name,
				Email: user.Email,
				Role:  user.Role,
			},
			"edition": edition,
		})
	}
}

func editionForRole(role, requested string) string {
	requested = strings.ToLower(strings.TrimSpace(requested))
	if requested == "oss" || requested == "enterprise" {
		return requested
	}
	if role == "admin" || role == "operator" {
		return "enterprise"
	}
	return "oss"
}
