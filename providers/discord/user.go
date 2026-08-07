package discord

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	gociconnect "github.com/only1enes/goci-connect"
)

type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	GlobalName    string `json:"global_name"`
	Discriminator string `json:"discriminator"`
	Email         string `json:"email"`
	Avatar        string `json:"avatar"`
}

func mapUser(raw json.RawMessage) (gociconnect.User, error) {
	var source discordUser
	if err := json.Unmarshal(raw, &source); err != nil {
		return gociconnect.User{}, decodingError()
	}
	id := strings.TrimSpace(source.ID)
	userID, err := strconv.ParseUint(id, 10, 64)
	if err != nil {
		return gociconnect.User{}, decodingError()
	}
	name := strings.TrimSpace(source.GlobalName)
	if name == "" {
		name = strings.TrimSpace(source.Username)
	}
	return gociconnect.User{
		ID:        id,
		Nickname:  strings.TrimSpace(source.Username),
		Name:      name,
		Email:     strings.TrimSpace(source.Email),
		AvatarURL: avatarURL(id, userID, source.Discriminator, source.Avatar),
	}, nil
}

func avatarURL(id string, userID uint64, discriminator, avatar string) string {
	if avatar = strings.TrimSpace(avatar); avatar != "" {
		return fmt.Sprintf("%s/avatars/%s/%s.png", cdnBaseURL, id, url.PathEscape(avatar))
	}
	discriminator = strings.TrimSpace(discriminator)
	var index uint64
	if discriminator == "0" {
		index = (userID >> 22) % 6
	} else {
		legacy, err := strconv.ParseUint(discriminator, 10, 64)
		if err != nil {
			return ""
		}
		index = legacy % 5
	}
	return fmt.Sprintf("%s/embed/avatars/%d.png", cdnBaseURL, index)
}

func decodingError() error {
	return gociconnect.NewError(gociconnect.ErrorCodeDecoding, providerName, "map Discord user", nil)
}
