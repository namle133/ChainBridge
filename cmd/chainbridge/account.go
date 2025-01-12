// Copyright 2020 ChainSafe Systems
// SPDX-License-Identifier: LGPL-3.0-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ChainSafe/ChainBridge/config"
	"github.com/ChainSafe/chainbridge-utils/crypto"
	"github.com/ChainSafe/chainbridge-utils/crypto/secp256k1"
	"github.com/ChainSafe/chainbridge-utils/crypto/sr25519"
	"github.com/ChainSafe/chainbridge-utils/hash"
	"github.com/ChainSafe/chainbridge-utils/keystore"
	log "github.com/ChainSafe/log15"
	gokeystore "github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/urfave/cli/v2"
)

var (
	RelayerPrivateKeyFlag = "SRC_PK"
	EnvFileName = ".env"
)

//dataHandler is a struct which wraps any extra data our CMD functions need that cannot be passed through parameters
type dataHandler struct {
	datadir string
}

// wrapHandler takes in a Cmd function (all declared below) and wraps
// it in the correct signature for the Cli Commands
func wrapHandler(hdl func(*cli.Context, *dataHandler) error) cli.ActionFunc {

	return func(ctx *cli.Context) error {
		err := startLogger(ctx)
		if err != nil {
			return err
		}

		datadir, err := getDataDir(ctx)
		if err != nil {
			return fmt.Errorf("failed to access the datadir: %w", err)
		}

		return hdl(ctx, &dataHandler{datadir: datadir})
	}
}

// handleGenerateCmd generates a keystore for the accounts
func handleGenerateCmd(ctx *cli.Context, dHandler *dataHandler) error {

	log.Info("Generating keypair...")

	// check if --ed25519 or --sr25519 is set
	keytype := crypto.Secp256k1Type
	if flagtype := ctx.Bool(config.Sr25519Flag.Name); flagtype {
		keytype = crypto.Sr25519Type
	} else if flagtype := ctx.Bool(config.Secp256k1Flag.Name); flagtype {
		keytype = crypto.Secp256k1Type
	}

	// check if --password is set
	var password []byte = nil
	if pwdflag := ctx.String(config.PasswordFlag.Name); pwdflag != "" {
		password = []byte(pwdflag)
	}

	_, err := generateKeypair(keytype, dHandler.datadir, password, ctx.String(config.SubkeyNetworkFlag.Name))
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	return nil
}

// handleImportCmd imports external keystores into the bridge
func handleImportCmd(ctx *cli.Context, dHandler *dataHandler) error {
	log.Info("Importing key...")
	var err error

	// check if --ed25519 or --sr25519 is set
	keytype := crypto.Secp256k1Type
	if flagtype := ctx.Bool(config.Sr25519Flag.Name); flagtype {
		keytype = crypto.Sr25519Type
	} else if flagtype := ctx.Bool(config.Secp256k1Flag.Name); flagtype {
		keytype = crypto.Secp256k1Type
	}

	if ctx.Bool(config.EthereumImportFlag.Name) {
		if keyimport := ctx.Args().First(); keyimport != "" {
			// check if --password is set
			var password []byte = nil
			if pwdflag := ctx.String(config.PasswordFlag.Name); pwdflag != "" {
				password = []byte(pwdflag)
			}
			_, err = importEthKey(keyimport, dHandler.datadir, password, nil)
		} else {
			return fmt.Errorf("Must provide a key to import.")
		}
	}else if privkeyflag := ctx.String(config.PrivateKeyFlag.Name); privkeyflag != "" {
		_, err = importPrivKey(ctx, keytype, dHandler.datadir)
	}else {
		if keyimport := ctx.Args().First(); keyimport != "" {
			_, err = importKey(keyimport, dHandler.datadir)
		} else {
			return fmt.Errorf("Must provide a key to import.")
		}
	}

	if err != nil {
		return fmt.Errorf("failed to import key: %w", err)
	}

	return nil
}

// handleListCmd lists all accounts currently in the bridge
func handleListCmd(ctx *cli.Context, dHandler *dataHandler) error {

	_, err := listKeys(dHandler.datadir)
	if err != nil {
		return fmt.Errorf("failed to list keys: %w", err)
	}

	return nil
}

// getDataDir obtains the path to the keystore and returns it as a string
func getDataDir(ctx *cli.Context) (string, error) {
	// key directory is datadir/keystore/
	if dir := ctx.String(config.KeystorePathFlag.Name); dir != "" {
		datadir, err := filepath.Abs(dir)
		if err != nil {
			return "", err
		}
		log.Trace(fmt.Sprintf("Using keystore dir: %s", datadir))
		return datadir, nil
	}
	return "", fmt.Errorf("datadir flag not supplied")
}

func ValidatePassword(password string) bool {
	// Define password constraints
	minLength := 10
	hasUppercase := false
	hasLowercase := false
	hasNumber := false
	hasSpecialChar := false

	// Check length constraints
	if len(password) < minLength {
		log.Error("Please set a password at least 10 charaters")
		return false
	}

	// Check for other constraints using regular expressions
	uppercaseRegex := regexp.MustCompile(`[A-Z]`)
	lowercaseRegex := regexp.MustCompile(`[a-z]`)
	numberRegex := regexp.MustCompile(`[0-9]`)
	specialCharRegex := regexp.MustCompile(`[^a-zA-Z0-9]`)

	hasUppercase = uppercaseRegex.MatchString(password)
	hasLowercase = lowercaseRegex.MatchString(password)
	hasNumber = numberRegex.MatchString(password)
	hasSpecialChar = specialCharRegex.MatchString(password)

	if (!hasUppercase) {
		log.Error("Please type at least one capital letter")
		return false
	}
	if (!hasLowercase) {
		log.Error("Please type at least one lower letter")
		return false
	}
	if (!hasNumber) {
		log.Error("Please type at least one number")
		return false
	}
	if (!hasSpecialChar) {
		log.Error("Please type at least one special char")
		return false
	}

	return true
}

func updateEnvVariable(filename, key, value string) error {
	// Read the content of the environment file
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")

	// Find the line with the key and update its value
	var updatedContent []string
	found := false
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			updatedContent = append(updatedContent, fmt.Sprintf("%s=%s", key, value))
			found = true
		} else {
			updatedContent = append(updatedContent, line)
		}
	}

	// If the key was not found, append it to the content
	if !found {
		updatedContent = append(updatedContent, fmt.Sprintf("%s=%s", key, value))
	}

	// Join the content lines
	newContent := strings.Join(updatedContent, "\n")

	// Write the updated content back to the file
	err = ioutil.WriteFile(filename, []byte(newContent), 0644)
	if err != nil {
		return err
	}

	return nil
}

//importPrivKey imports a private key into a keypair
func importPrivKey(ctx *cli.Context, keytype string, datadir string) (string, error) {
	key := ctx.String(config.PrivateKeyFlag.Name)
	fmt.Println(config.PrivateKeyFlag.Name)
	// update private key in env file 
	// updateEnvVariable(EnvFileName, RelayerPrivateKeyFlag, "00000")

	var password []byte
	var passwordRetype []byte
	if password == nil {
		for {
			password = keystore.GetPassword("Enter password to encrypt keystore file (10 characters minimum. Must include capital, small case, number, and punctuation mark): ")
			for(!ValidatePassword(string(password))) {
				password = keystore.GetPassword("Input error. Please type password (10 characters minimum. Must include capital, small case, number, and punctuation mark): ")
			}
			passwordRetype = keystore.GetPassword("Re-enter same password to verify: ")
			if bytes.Equal(password, passwordRetype) {
				for i:= 0; i < len(passwordRetype); i++ {
					passwordRetype[i] = 0
				}
				log.Info("Password created successfully")
				break
			}
			for i:= 0; i < len(passwordRetype); i++ {
				passwordRetype[i] = 0
			}
			for i:= 0; i < len(password); i++ {
				password[i] = 0
			}
		}
	}
	keystorepath, err := keystoreDir(datadir)

	if keytype == "" {
		log.Info("Using default key type", "type", keytype)
		keytype = crypto.Secp256k1Type
	}

	var kp crypto.Keypair
	hshPwd, salt, err := hash.HashPasswordIteratively(password)
	for i := 0; i < len(password); i++ {
		password[i] = 0
	}
	if err != nil {

		for i := 0; i < len(hshPwd); i++ {
			hshPwd[i] = 0
		}
		for i := 0; i < len(salt); i++ {
			salt[i] = 0
		}
		
		return "", err
	}

	if keytype == crypto.Sr25519Type {
		// generate sr25519 keys
		network := ctx.String(config.SubkeyNetworkFlag.Name)
		kp, err = sr25519.NewKeypairFromSeed(key, network)
		if err != nil {
			for i := 0; i < len(hshPwd); i++ {
				hshPwd[i] = 0
			}
			for i := 0; i < len(salt); i++ {
				salt[i] = 0
			}
			kp.DeleteKeyPair()
			kp =  nil
			return "", fmt.Errorf("could not generate sr25519 keypair from given string: %w", err)
		}
	} else if keytype == crypto.Secp256k1Type {
		// Hex must not have leading 0x
		if key[0:2] == "0x" {
			kp, err = secp256k1.NewKeypairFromString(key[2:])
		} else {
			kp, err = secp256k1.NewKeypairFromString(key)
		}

		if err != nil {
			for i := 0; i < len(hshPwd); i++ {
				hshPwd[i] = 0
			}
			for i := 0; i < len(salt); i++ {
				salt[i] = 0
			}
			kp.DeleteKeyPair()
			kp =  nil
			return "", fmt.Errorf("could not generate secp256k1 keypair from given string: %w", err)
		}
	} else {
		for i := 0; i < len(hshPwd); i++ {
			hshPwd[i] = 0
		}
		for i := 0; i < len(salt); i++ {
			salt[i] = 0
		}
		return "", fmt.Errorf("invalid key type: %s", keytype)
	}

	fp, err := filepath.Abs(keystorepath + "/" + kp.Address() + ".key")
	if err != nil {
		for i := 0; i < len(hshPwd); i++ {
			hshPwd[i] = 0
		}
		for i := 0; i < len(salt); i++ {
			salt[i] = 0
		}
		kp.DeleteKeyPair()
		kp =  nil
		return "", fmt.Errorf("invalid filepath: %w", err)
	}

	file, err := os.OpenFile(filepath.Clean(fp), os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		for i := 0; i < len(hshPwd); i++ {
			hshPwd[i] = 0
		}
		for i := 0; i < len(salt); i++ {
			salt[i] = 0
		}
		kp.DeleteKeyPair()
		kp =  nil
		return "", fmt.Errorf("Unable to Open File: %w", err)
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Error("import private key: could not close keystore file")
		}
	}()
	
	hshPwd = append(hshPwd, salt...)

	err = keystore.EncryptAndWriteToFile(file, kp, hshPwd)
	if err != nil {
		for i := 0; i < len(hshPwd); i++ {
			hshPwd[i] = 0
		}
		for i := 0; i < len(salt); i++ {
			salt[i] = 0
		}

		kp.DeleteKeyPair()
		return "", fmt.Errorf("could not write key to file: %w", err)
	}
	for i := 0; i < len(hshPwd); i++ {
		hshPwd[i] = 0
	}
	for i := 0; i < len(salt); i++ {
		salt[i] = 0
	}
	log.Info("private key imported", "address", kp.Address(), "file", fp)
	// kp.DeleteKeyPair()
	return fp, nil

}

//importEthKey takes an ethereum keystore and converts it to our keystore format
func importEthKey(filename, datadir string, password, newPassword []byte) (string, error) {
	keystorepath, err := keystoreDir(datadir)
	if err != nil {
		return "", fmt.Errorf("could not get keystore directory: %w", err)
	}

	importdata, err := ioutil.ReadFile(filepath.Clean(filename))
	if err != nil {
		return "", fmt.Errorf("could not read import file: %w", err)
	}

	if password == nil {
		password = keystore.GetPassword("Enter password to decrypt keystore file:")
	}

	key, err := gokeystore.DecryptKey(importdata, string(password))
	if err != nil {
		return "", fmt.Errorf("Unable to decrypt file: %w", err)
	}

	kp := secp256k1.NewKeypair(*key.PrivateKey)

	fp, err := filepath.Abs(keystorepath + "/" + kp.Address() + ".key")
	if err != nil {
		return "", fmt.Errorf("invalid filepath: %w", err)
	}

	file, err := os.OpenFile(filepath.Clean(fp), os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Error("generate keypair: could not close keystore file")
		}
	}()

	if newPassword == nil {
		newPassword = keystore.GetPassword("Enter password to encrypt new keystore file:")
	}

	hshPwd, salt, err := hash.HashPasswordIteratively(newPassword)
	if err != nil {
		return "", err
	}
	hshPwd = append(hshPwd, salt...)
	err = keystore.EncryptAndWriteToFile(file, kp, hshPwd)
	
	if err != nil {
		return "", fmt.Errorf("could not write key to file: %w", err)
	}

	log.Info("ETH key imported", "address", kp.Address(), "file", fp)
	return fp, nil

}

// importKey imports a key specified by its filename to datadir/keystore/
// it saves it under the filename "[publickey].key"
// it returns the absolute path of the imported key file
func importKey(filename, datadir string) (string, error) {
	keystorepath, err := keystoreDir(datadir)
	if err != nil {
		return "", fmt.Errorf("could not get keystore directory: %w", err)
	}

	importdata, err := ioutil.ReadFile(filepath.Clean(filename))
	if err != nil {
		return "", fmt.Errorf("could not read import file: %w", err)
	}

	ksjson := new(keystore.EncryptedKeystore)
	err = json.Unmarshal(importdata, ksjson)
	if err != nil {
		return "", fmt.Errorf("could not read file contents: %w", err)
	}

	keystorefile, err := filepath.Abs(keystorepath + "/" + ksjson.Address[2:] + ".key")
	if err != nil {
		return "", fmt.Errorf("could not create keystore file path: %w", err)
	}

	err = ioutil.WriteFile(keystorefile, importdata, 0600)
	if err != nil {
		return "", fmt.Errorf("could not write to keystore directory: %w", err)
	}

	log.Info("successfully imported key", "address", ksjson.Address, "file", keystorefile)
	return keystorefile, nil
}

// listKeys lists all the keys in the datadir/keystore/ directory and returns them as a list of filepaths
func listKeys(datadir string) ([]string, error) {
	keys, err := getKeyFiles(datadir)
	if err != nil {
		return nil, err
	}

	fmt.Printf("=== Found %d keys ===\n", len(keys))
	for i, key := range keys {
		fmt.Printf("[%d] %s\n", i, key)
	}

	return keys, nil
}

// getKeyFiles returns the filenames of all the keys in the datadir's keystore
func getKeyFiles(datadir string) ([]string, error) {
	keystorepath, err := keystoreDir(datadir)
	if err != nil {
		return nil, fmt.Errorf("could not get keystore directory: %w", err)
	}

	files, err := ioutil.ReadDir(keystorepath)
	if err != nil {
		return nil, fmt.Errorf("could not read keystore dir: %w", err)
	}

	keys := []string{}

	for _, f := range files {
		ext := filepath.Ext(f.Name())
		if ext == ".key" {
			keys = append(keys, f.Name())
		}
	}

	return keys, nil
}

// generateKeypair create a new keypair with the corresponding type and saves it to datadir/keystore/[public key].key
// in json format encrypted using the specified password
// it returns the resulting filepath of the new key
func generateKeypair(keytype, datadir string, password []byte, subNetwork string) (string, error) {
	if password == nil {
		password = keystore.GetPassword("Enter password to encrypt keystore file:")
	}

	if keytype == "" {
		log.Info("Using default key type", "type", keytype)
		keytype = crypto.Secp256k1Type
	}

	var kp crypto.Keypair
	var err error

	hshPwd, salt, err := hash.HashPasswordIteratively(password)
	if err != nil {
		return "", err
	}

	if keytype == crypto.Sr25519Type {
		// generate sr25519 keys
		kp, err = sr25519.GenerateKeypair(subNetwork)
		if err != nil {
			return "", fmt.Errorf("could not generate sr25519 keypair: %w", err)
		}
	} else if keytype == crypto.Secp256k1Type {
		// generate secp256k1 keys
		kp, err = secp256k1.GenerateKeypair()
		if err != nil {
			return "", fmt.Errorf("could not generate secp256k1 keypair: %w", err)
		}
	} else {
		return "", fmt.Errorf("invalid key type: %s", keytype)
	}

	keystorepath, err := keystoreDir(datadir)
	if err != nil {
		return "", fmt.Errorf("could not get keystore directory: %w", err)
	}

	fp, err := filepath.Abs(keystorepath + "/" + kp.Address() + ".key")
	if err != nil {
		return "", fmt.Errorf("invalid filepath: %w", err)
	}

	file, err := os.OpenFile(filepath.Clean(fp), os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}

	defer func() {
		err = file.Close()
		if err != nil {
			log.Error("generate keypair: could not close keystore file")
		}
	}()
	
	hshPwd = append(hshPwd, salt...)
	err = keystore.EncryptAndWriteToFile(file, kp, hshPwd)
	if err != nil {
		return "", fmt.Errorf("could not write key to file: %w", err)
	}

	log.Info("key generated", "address", kp.Address(), "type", keytype, "file", fp)
	return fp, nil
}

// keystoreDir returnns the absolute filepath of the keystore directory given a datadir
// by default, it is ./keys/
// otherwise, it is datadir/keys/
func keystoreDir(keyPath string) (keystorepath string, err error) {
	// datadir specified, return datadir/keys as absolute path
	if keyPath != "" {
		keystorepath, err = filepath.Abs(keyPath)
		if err != nil {
			return "", err
		}
	} else {
		// datadir not specified, use default
		keyPath = config.DefaultKeystorePath

		keystorepath, err = filepath.Abs(keyPath)
		if err != nil {
			return "", fmt.Errorf("could not create keystore file path: %w", err)
		}
	}

	// if datadir does not exist, create it
	if _, err = os.Stat(keyPath); os.IsNotExist(err) {
		err = os.Mkdir(keyPath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	// if datadir/keystore does not exist, create it
	if _, err = os.Stat(keystorepath); os.IsNotExist(err) {
		err = os.Mkdir(keystorepath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	return keystorepath, nil
}
