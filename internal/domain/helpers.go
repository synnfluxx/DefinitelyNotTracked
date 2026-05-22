package domain

import (
	"encoding/base64"
	"strings"
)

func DecodeBase64Sub(b64Str string) (string, error) {
	b64Str = strings.TrimSpace(b64Str)

	if len(b64Str)%4 != 0 {
		b64Str += strings.Repeat("=", 4-(len(b64Str)%4))
	}

	decoded, err := base64.StdEncoding.DecodeString(b64Str)
	if err != nil {
		decoded, err = base64.URLEncoding.DecodeString(b64Str)
		if err != nil {
			return "", err
		}
	}

	return string(decoded), nil
}
