package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	b64 "encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tursodatabase/go-libsql"

	_ "modernc.org/sqlite"
)

type Secret struct {
	Name  string
	Value string
}

type SecretRow struct {
	ID int
	Secret
}

var (
	// We're using a 32 byte long secret key
	secretKey = "RWW5vPO86Ldy2iKW2XzwHD37tOmGMvgz" // Not so secret yet ;-)
)

func encrypt(plaintext string) string {
	aesCipher, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	// We need a 12-byte nonce for GCM (modifiable if you use cipher.NewGCMWithNonceSize())
	// A nonce should always be randomly generated for every encryption.
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		panic(err)
	}

	// ciphertext here is actually nonce+ciphertext
	// So that when we decrypt, just knowing the nonce size
	// is enough to separate it from the ciphertext.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return string(ciphertext)
}

func decrypt(ciphertext string) string {
	aesCipher, err := aes.NewCipher([]byte(secretKey))
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic(err)
	}

	// Since we know the ciphertext is actually nonce+ciphertext
	// And len(nonce) == NonceSize(). We can separate the two.
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		panic(err)
	}

	return string(plaintext)
}

func storeSecret(db *sql.DB, name string, value string) error {
	_, err := fetchSecret(db, name)

	if err == nil {
		return nil
	}

	var encrypted = encrypt(value)

	base64Encoded := b64.StdEncoding.EncodeToString([]byte(encrypted))

	_, err = db.ExecContext(
		context.Background(),
		`INSERT INTO secret_store (name, value) VALUES (?, ?)`,
		name, base64Encoded,
	)

	if err != nil {
		return err
	}

	println("All good: inserted secret in DB")
	return nil
}

func fetchSecret(db *sql.DB, name string) (string, error) {
	var secret SecretRow

	row := db.QueryRowContext(
		context.Background(),
		`SELECT * FROM secret_store WHERE name=?`, name,
	)

	err := row.Scan(&secret.ID, &secret.Name, &secret.Value)
	if err != nil {
		return "Could not get secret", err
	}

	decrypted := decrypt(secret.Value)

	base64Decoded, _ := b64.StdEncoding.DecodeString(decrypted)

	println("All good: fetched secret in DB")
	return string(base64Decoded), nil
}

func initDb(path string) (*sql.DB, error) {
	dbName := path
	primaryUrl := os.Getenv("TURSO_DATABASE_URL")
	authToken := os.Getenv("TURSO_AUTH_TOKEN")

	dir, err := os.MkdirTemp("", "libsql-*")
	if err != nil {
		fmt.Println("Error creating temporary directory:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	dbPath := filepath.Join(dir, dbName)

	connector, err := libsql.NewEmbeddedReplicaConnector(dbPath, primaryUrl,
		libsql.WithAuthToken(authToken),
	)
	if err != nil {
		fmt.Println("Error creating connector:", err)
		os.Exit(1)
	}
	defer connector.Close()

	db := sql.OpenDB(connector)

	_, err = db.ExecContext(
		context.Background(),
		`CREATE TABLE IF NOT EXISTS secret_store (
			id INTEGER PRIMARY KEY AUTOINCREMENT, 
			name TEXT NOT NULL, 
			value TEXT NOT NULL
		)`,
	)
	if err != nil {
		println("error creating table:", err.Error())
		return nil, err
	}

	return db, nil
}

func main() {
	db, err := initDb("test.db")

	if err != nil {
		panic(err)
	}

	err = storeSecret(db, "some_sexy_secret", "shhhh_test_data")

	if err != nil {
		panic(err)
	}

	secret, err := fetchSecret(db, "some_sexy_secret")

	println("Secret: ", secret)
}
