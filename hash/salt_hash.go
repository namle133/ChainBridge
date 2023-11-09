package hash

import (
	"crypto/sha512"
)

var salt = []byte("3.14159265358979323846")

// Combine password and salt then hash them using the SHA-512
// hashing algorithm and then return the hashed password
// as a base64 encoded string
func HashPassword(password string) ([]byte, error) {
	// Convert password string to byte slice
	var passwordBytes = []byte(password)

	// Create sha-512 hasher
	var sha512Hasher = sha512.New()

	// Append salt to password
	passwordBytes = append(passwordBytes, salt...)

	// Write password bytes to the hasher
	_, err := sha512Hasher.Write(passwordBytes)
	if err != nil {
		return nil, err
	}

	// Get the SHA-512 hashed password
	var hashedPasswordBytes = sha512Hasher.Sum(nil)

	return hashedPasswordBytes, nil
}
