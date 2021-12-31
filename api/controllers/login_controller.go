package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dchest/captcha"

	"web-backend/api/auth"
	"web-backend/api/models"
	"web-backend/api/security"
	"web-backend/api/utils/formaterror"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) Login(c *gin.Context) {

	body := map[string]string{}

	//clear previous error if any
	errList = map[string]string{}

	if err := json.NewDecoder(c.Request.Body).Decode(&body); err != nil {
		errList["Invalid_body"] = "Unable to get request"
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errList,
		})
		return
	}

	user := models.User{
		Email:    body["email"],
		Password: body["password"],
	}

	user.Prepare()
	errorMessages := user.Validate("login")
	if len(errorMessages) > 0 {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  errorMessages,
		})
		return
	}
	if check := captcha.VerifyString(body["captcha_id"], body["captcha_value"]); !check {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error": gin.H{
				"invalid_captcha": "Wrong captcha",
			},
		})
		return
	}

	userData, err := s.SignIn(user.Email, user.Password)
	if err != nil {
		formattedError := formaterror.FormatError(err.Error())
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"status": http.StatusUnprocessableEntity,
			"error":  formattedError,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": userData,
	})
}

func (s *Server) SignIn(email, password string) (map[string]interface{}, error) {

	var err error

	userData := make(map[string]interface{})

	user := models.User{}

	err = s.DB.Debug().Model(models.User{}).Where("email = ?", email).Take(&user).Error
	if err != nil {
		fmt.Println("this is the error getting the user: ", err)
		return nil, err
	}
	err = security.VerifyPassword(user.Password, password)
	if err != nil && err == bcrypt.ErrMismatchedHashAndPassword {
		fmt.Println("this is the error hashing the password: ", err)
		return nil, err
	}
	token, err := auth.CreateToken(user.ID)
	if err != nil {
		fmt.Println("this is the error creating the token: ", err)
		return nil, err
	}
	userData["token"] = token
	userData["id"] = user.ID
	userData["email"] = user.Email
	userData["avatar_path"] = user.AvatarPath
	userData["username"] = user.Username

	return userData, nil
}
