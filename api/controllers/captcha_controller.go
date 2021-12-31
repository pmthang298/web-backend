package controllers

import (
	"net/http"

	"github.com/dchest/captcha"
	"github.com/gin-gonic/gin"
)

var (
	dWitch  = 200
	dHeight = 100
)

func (s *Server) InitCaptcha(c *gin.Context) {
	resp := map[string]string{
		"id": captcha.New(),
	}
	c.JSON(http.StatusOK, gin.H{
		"status":   http.StatusOK,
		"response": resp,
	})
}

func (s *Server) GetCaptchaImage(c *gin.Context) {
	captchaId := c.Param("id")
	// c.Writer.WriteHeader(http.StatusOK)
	captcha.Reload(captchaId)
	if err := captcha.WriteImage(c.Writer, captchaId, dWitch, dHeight); err != nil {
		if err == captcha.ErrNotFound {
			c.JSON(http.StatusNotFound, gin.H{
				"status":          404,
				"invalid_captcha": "Not Found",
			})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": 500,
			"error": gin.H{
				"invalid_captcha": "Internal server error",
			},
		})
	}
}
