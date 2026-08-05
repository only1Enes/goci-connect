package google

import (
	"encoding/json"
	"strings"

	gociconnect "github.com/only1enes/goci-connect"
)

type userInfo struct {
	Subject       string `json:"sub"`
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified *bool  `json:"email_verified"`
	Picture       string `json:"picture"`
}

func mapUserInfo(raw json.RawMessage) (gociconnect.User, error) {
	var source userInfo
	if err := json.Unmarshal(raw, &source); err != nil {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeDecoding, providerName, "map Google user", nil)
	}
	subject := strings.TrimSpace(source.Subject)
	if subject == "" {
		return gociconnect.User{}, gociconnect.NewError(gociconnect.ErrorCodeDecoding, providerName, "map Google user", nil)
	}
	return gociconnect.User{
		ID:        subject,
		Name:      source.Name,
		Email:     strings.TrimSpace(source.Email),
		AvatarURL: source.Picture,
	}, nil
}
