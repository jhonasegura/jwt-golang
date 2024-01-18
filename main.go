package main

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Clave secreta para firmar y verificar el token. Deberías guardar esto de manera segura.
var jwtKey = []byte("tu_clave_secreta")

// User struct para demostrar cómo puedes incluir información del usuario en el token.
type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
}

// Función para generar un nuevo token JWT.
func generateToken(user User) (string, error) {
	// Definir los claims del token.
	claims := jwt.MapClaims{
		"id":       user.ID,
		"username": user.Username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(), // Token expirará en 24 horas.
	}

	// Crear el token con los claims y firmarlo con la clave secreta.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Función para verificar y decodificar un token JWT.
func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verificar el método de firma.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Método de firma no válido")
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	return token, nil
}

func main() {
	// Ejemplo de generación de token
	user := User{
		ID:       1,
		Username: "ejemplo",
	}

	token, err := generateToken(user)
	if err != nil {
		fmt.Println("Error al generar el token:", err)
		return
	}

	fmt.Println("Token generado:", token)

	// Ejemplo de verificación de token
	verifiedToken, err := verifyToken(token)
	if err != nil {
		fmt.Println("Error al verificar el token:", err)
		return
	}

	fmt.Println("Token verificado:", verifiedToken)
}
