package gitlab

import (
	"encoding/json"
	"strconv"
	"strings"

	gociconnect "github.com/only1enes/goci-connect"
)

type gitlabUser struct {
	ID          json.Number `json:"id"`
	Username    string      `json:"username"`
	Name        string      `json:"name"`
	Email       string      `json:"email"`
	PublicEmail string      `json:"public_email"`
	AvatarURL   string      `json:"avatar_url"`
}

func mapUser(raw json.RawMessage) (gociconnect.User, error) {
	var source gitlabUser
	if err := json.Unmarshal(raw, &source); err != nil {
		return gociconnect.User{}, decodingError()
	}
	id, err := strconv.ParseUint(source.ID.String(), 10, 64)
	if err != nil {
		return gociconnect.User{}, decodingError()
	}
	email := strings.TrimSpace(source.Email)
	if email == "" {
		email = strings.TrimSpace(source.PublicEmail)
	}
	return gociconnect.User{
		ID:        strconv.FormatUint(id, 10),
		Nickname:  strings.TrimSpace(source.Username),
		Name:      source.Name,
		Email:     email,
		AvatarURL: source.AvatarURL,
	}, nil
}

func decodingError() error {
	return gociconnect.NewError(gociconnect.ErrorCodeDecoding, providerName, "map GitLab user", nil)
}
