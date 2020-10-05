package gocloaksession

import (
	"context"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v7"
	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
)

// CallOption configures a Session
type CallOption func(*goCloakSession) error

// RequestSkipper is a function signature that can be used to skip a certain
// request if needed.
type RequestSkipper func(*resty.Request) bool

// SubstringRequestSkipper is a RequestSkipper that skips a request when the
// url in the request contains a certain substring
func SubstringRequestSkipper(substr string) RequestSkipper {
	return func(r *resty.Request) bool {
		return strings.Contains(r.URL, substr)
	}
}

// RequestSkipperCallOption appends a RequestSkipper to the skipConditions
func RequestSkipperCallOption(requestSkipper RequestSkipper) CallOption {
	return func(gcs *goCloakSession) error {
		gcs.skipConditions = append(gcs.skipConditions, requestSkipper)
		return nil
	}
}

// PrematureRefreshThresholdOption sets the threshold for a premature token
// refresh
func PrematureRefreshThresholdOption(accessToken, refreshToken time.Duration) CallOption {
	return func(gcs *goCloakSession) error {
		gcs.prematureRefreshTokenRefreshThreshold = int(refreshToken.Seconds())
		gcs.prematureAccessTokenRefreshThreshold = int(accessToken.Seconds())
		return nil
	}
}

type goCloakSession struct {
	clientID                              string
	clientSecret                          string
	realm                                 string
	gocloak                               gocloak.GoCloak
	token                                 *gocloak.JWT
	lastRequest                           time.Time
	skipConditions                        []RequestSkipper
	prematureRefreshTokenRefreshThreshold int
	prematureAccessTokenRefreshThreshold  int
}

// NewSession returns a new instance of a gocloak Session
func NewSession(clientID, clientSecret, realm, uri string, calloptions ...CallOption) (GoCloakSession, error) {
	session := &goCloakSession{
		clientID:                              clientID,
		clientSecret:                          clientSecret,
		realm:                                 realm,
		gocloak:                               gocloak.NewClient(uri),
		prematureAccessTokenRefreshThreshold:  0,
		prematureRefreshTokenRefreshThreshold: 0,
	}

	for _, option := range calloptions {
		err := option(session)
		if err != nil {
			return nil, errors.Wrap(err, "error while applying option")
		}
	}

	return session, nil
}

func (session *goCloakSession) ForceAuthenticate() error {
	return session.authenticate(nil)
}

func (session *goCloakSession) ForceRefresh() error {
	return session.refreshToken(nil)
}

func (session *goCloakSession) GetKeycloakAuthToken() (*gocloak.JWT, error) {
	return session.getKeycloakAuthToken(zerolog.Nop())
}

func (session *goCloakSession) getKeycloakAuthToken(logger zerolog.Logger) (*gocloak.JWT, error) {
	logger.Info().Msg("3.1. accesstoken")
	if session.isAccessTokenValid(logger) {
		logger.Info().Msg("3.1.4 accesstoken is valid")
		return session.token, nil
	}

	logger.Info().Msg("3.2. refreshtoken")
	if session.isRefreshTokenValid(logger) {
		logger.Info().Msg("3.2.3 refreshtoken is Valid, refreshing ...")
		err := session.refreshToken(&logger)
		if err == nil {
			return session.token, nil
		}
	}

	logger.Info().Msg("3.3. authenticate")
	err := session.authenticate(&logger)
	if err != nil {
		logger.Error().Err(err)
		return nil, err
	}

	return session.token, nil
}

func (session *goCloakSession) isAccessTokenValid(logger zerolog.Logger) bool {
	if session.token == nil {
		logger.Info().Msg("3.1.0 session is nil")
		return false
	}

	if session.lastRequest.IsZero() {
		logger.Info().Msg("3.1.1 lastRequest is zero")
		return false
	}

	sessionExpiry := session.token.ExpiresIn - session.prematureAccessTokenRefreshThreshold
	secondsSinceLastAuthentication := int(time.Since(session.lastRequest).Seconds())
	isExpired := secondsSinceLastAuthentication > sessionExpiry

	logger.Info().Msgf("3.1.2 sessionExpiry: %d\nsecondsSinceLastAuthentication: %d\nisExpired: %t\n", sessionExpiry, secondsSinceLastAuthentication, isExpired)
	if isExpired {
		return false
	}

	token, _, err := session.gocloak.DecodeAccessToken(context.Background(), session.token.AccessToken, session.realm, "")

	logger.Info().Err(err).Msgf("3.1.3 token.Valid: %t\n", token.Valid)
	return err == nil && token.Valid
}

func (session *goCloakSession) isRefreshTokenValid(logger zerolog.Logger) bool {
	if session.token == nil {
		logger.Info().Msg("3.2.0 session is nil")
		return false
	}

	if session.lastRequest.IsZero() {
		logger.Info().Msg("3.2.1 lastRequest is zero")
		return false
	}

	sessionExpiry := session.token.RefreshExpiresIn - session.prematureRefreshTokenRefreshThreshold
	secondsSinceLastAuthentication := int(time.Since(session.lastRequest).Seconds())
	isExpired := secondsSinceLastAuthentication > sessionExpiry

	logger.Info().Msgf("3.2.2 sessionExpiry: %d\nsecondsSinceLastAuthentication: %d\nisExpired: %t\n", sessionExpiry, secondsSinceLastAuthentication, isExpired)

	return !isExpired
}

func (session *goCloakSession) refreshToken(logger *zerolog.Logger) error {
	session.lastRequest = time.Now()

	jwt, err := session.gocloak.RefreshToken(context.Background(), session.token.RefreshToken, session.clientID, session.clientSecret, session.realm)
	if err != nil {
		if logger != nil {
			logger.Error().Err(err)
		}
		return errors.Wrap(err, "could not refresh keycloak-token")
	}

	if logger != nil {
		logger.Info().Msgf("ExpiresIn: %d\nRefreshExpiresIn: %d\nLastRequest: %v",
			jwt.ExpiresIn,
			jwt.RefreshExpiresIn,
			session.lastRequest)
	}
	session.token = jwt

	return nil
}

func (session *goCloakSession) authenticate(logger *zerolog.Logger) error {
	session.lastRequest = time.Now()

	jwt, err := session.gocloak.LoginClient(context.Background(), session.clientID, session.clientSecret, session.realm)
	if err != nil {
		if logger != nil {
			logger.Error().Err(err).Msg("3.2.0")
		}
		return errors.Wrap(err, "could not login to keycloak")
	}

	if logger != nil {
		logger.Info().Msgf("3.2.1 ExpiresIn: %d\nRefreshExpiresIn: %d\nLastRequest: %v",
			jwt.ExpiresIn,
			jwt.RefreshExpiresIn,
			session.lastRequest)
	}

	session.token = jwt

	return nil
}

func (session *goCloakSession) AddAuthTokenToRequest(client *resty.Client, request *resty.Request) error {
	logger := zerolog.Ctx(request.Context()).With().
		Str("path", request.RawRequest.RequestURI).
		Str("RequestID", request.RawRequest.Header.Get("X-Request-ID")).Logger()

	logger.Info().Msg("1. AddAuthTokenToRequest")

	for _, shouldSkip := range session.skipConditions {
		if shouldSkip(request) {
			logger.Info().Msg("2. Skipping ... ")
			return nil
		}
	}

	logger.Info().Msg("3. GetKeycloakAuthToken")
	token, err := session.getKeycloakAuthToken(logger)
	if err != nil {
		// 4.
		logger.Error().Err(err)
		return err
	}

	if token.TokenType != "bearer" {
		logger.Info().Msg("5. bearer")
		request.SetAuthScheme(token.TokenType)
	}

	logger.Info().Msg("6. set Token")
	request.SetAuthToken(token.AccessToken)

	return nil
}

func (session *goCloakSession) GetGoCloakInstance() *gocloak.GoCloak {
	return &session.gocloak
}
