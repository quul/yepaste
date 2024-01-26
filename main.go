package main

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"github.com/matthewhartstonge/argon2"
	"github.com/quul/yepaste/model"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const identityKey = "id"
const maxLengthOfPasteKey = 32
const fixedLength = 6

var baseDomain = os.Getenv("BASE_URL")

func initDB() *gorm.DB {
	dbLink := os.Getenv("DATABASE_URL")
	db, err := gorm.Open(postgres.Open(dbLink), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to Database")
	}
	err = db.AutoMigrate(&model.User{})
	if err != nil {
		log.Fatal("Error while AutoMigrate User model")
	}
	err = db.AutoMigrate(&model.PasteContent{})
	if err != nil {
		log.Fatal("Error while AutoMigrate PasteContent model")
	}
	return db
}

func initJWT(db *gorm.DB) *jwt.GinJWTMiddleware {
	type login struct {
		Username string `form:"username" json:"username" binding:"required"`
		Password string `form:"password" json:"password" binding:"required"`
	}
	type User struct {
		UserName string
	}
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "yePaste",
		Key:         []byte(os.Getenv("JWT_KEY")),
		Timeout:     time.Hour * 24 * 30,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.UserName,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				UserName: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVal login
			if err := c.ShouldBind(&loginVal); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			username := loginVal.Username
			password := loginVal.Password

			var user model.User
			db.First(&user, "username = ?", username)
			if user.Username == "" { // No such user
				return nil, jwt.ErrFailedAuthentication
			}

			if ok, _ := argon2.VerifyEncoded([]byte(password), user.PasswordHash); ok {
				return &User{UserName: username}, nil
			}
			return nil, jwt.ErrFailedAuthentication // Wrong Password
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			if _, ok := data.(*User); ok {
				return true
			}
			return false
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		TokenLookup:    "header: Authorization, query: token, cookie: jwt",
		TokenHeadName:  "Bearer",
		TimeFunc:       time.Now,
		SendCookie:     true,
		CookieHTTPOnly: true,
	})
	if err != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + err.Error())
	}
	errInit := authMiddleware.MiddlewareInit()
	if errInit != nil {
		log.Fatal("authMiddleware.MiddlewareInit() Error:" + errInit.Error())
	}
	return authMiddleware
}

func checkKeyExist(key string, db *gorm.DB) bool {
	var pasteData model.PasteContent
	err := db.First(&pasteData, "key = ?", key).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return false
	}
	return true
}

func generateKey(fixedLength int) (string, error) {
	randBytes := make([]byte, fixedLength) // Directly using fixedLength here do waste some bytes.
	_, err := rand.Read(randBytes)
	if err != nil {
		return "", err
	}
	key := base32.StdEncoding.EncodeToString(randBytes)

	// We need 5 bits * 6 == 30 bits information
	// so slice the key to first 6 bytes
	key = key[:fixedLength]
	return key, nil
}

func main() {
	r := gin.Default()
	db := initDB()
	authMiddleware := initJWT(db)

	// Login Action
	r.POST("/a/login", authMiddleware.LoginHandler)
	// TODO: 自定义Cookie有效期

	// Get Content
	r.GET("/r/:key", func(c *gin.Context) {
		type ReqParam struct {
			Key string `uri:"key" binding:"required"`
		}
		var reqParam ReqParam
		if err := c.ShouldBindUri(&reqParam); err != nil {
			c.JSON(http.StatusNotAcceptable, gin.H{
				"code": http.StatusNotAcceptable,
				"msg":  err,
			})
			return
		}
		var content model.PasteContent
		result := db.First(&content, "key = ?", reqParam.Key)
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			c.JSON(http.StatusNotFound, gin.H{
				"code": http.StatusNotFound,
				"msg":  "Document Not Found",
			})
			return
		}

		// Disable the visit after expires.
		if content.ValidTill != nil && time.Now().Compare(*content.ValidTill) > 0 {
			c.JSON(http.StatusForbidden, gin.H{ // TODO: Maybe it always viewable for uploader?
				"code": http.StatusForbidden,
				"msg":  "Document expires",
			})
			return
		}

		// If there's a password, there will be an auth
		type ContentMeta struct {
			Password string `form:"pwd"`
		}
		var contentMeta ContentMeta
		if err := c.ShouldBind(&contentMeta); err != nil {
			log.Fatal("No password in", err) // This shouldn't be exec in theory
		}
		if content.Password != "" && content.Password != contentMeta.Password {
			c.JSON(http.StatusForbidden, gin.H{
				"code": http.StatusForbidden,
				"msg":  "Password Needed or password error",
			})
			return
		}

		c.Header("Language", content.ContentLanguage)
		c.Data(http.StatusOK, content.ContentType, content.Content)
		return
	})

	// Create new Content
	authorized := r.Group("/")
	authorized.Use(authMiddleware.MiddlewareFunc())
	{
		authorized.POST("/a/new", func(c *gin.Context) {
			// Get user model
			claims := jwt.ExtractClaims(c)
			username := claims[identityKey]
			var user model.User
			err := db.First(&user, "username = ?", username).Error
			if err != nil { // Actually I don't know why I had to handle this... JWT should already do this.
				c.JSON(http.StatusInternalServerError, gin.H{
					"code": http.StatusInternalServerError,
					"msg":  fmt.Sprintf("No such user named %s", username),
				})
				return
			}

			// Get metadata
			key := c.PostForm("key")
			expiresString := c.PostForm("expireTime")
			contentPassword := c.PostForm("password")
			contentType := c.PostForm("contentType")
			contentLanguage := c.PostForm("contentLanguage") // TODO: Validate the input
			contentFile, err := c.FormFile("c")
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code": http.StatusBadRequest,
					"msg":  fmt.Sprintf("Failed to parse file: %s", err),
				})
				return
			}
			file, err := contentFile.Open()
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code": http.StatusBadRequest,
					"msg":  fmt.Sprintf("Failed to parse file: %s", err),
				})
				return
			}
			uploadedContent, err := io.ReadAll(file) // TODO: Handle non text file and size limit
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{
					"code": http.StatusBadRequest,
					"msg":  fmt.Sprintf("Failed to parse file: %s", err),
				})
				return
			}
			defer func(file multipart.File) {
				err := file.Close()
				if err != nil {
					log.Fatal("Failed to close file")
				}
			}(file)
			if key != "" { // Check user provider key's validity, TODO: it sees that I should use validation via gin
				msg := ""
				if len(key) > maxLengthOfPasteKey {
					msg = "Key could not longer than " + string(rune(maxLengthOfPasteKey))
				} else if regexp.MustCompile(`^[a-zA-Z0-9]*$`).MatchString(key) {
					msg = "Key could only contain alphabet and numbers"
				}

				if msg != "" {
					c.JSON(http.StatusBadRequest, gin.H{
						"code": http.StatusBadRequest,
						msg:    msg,
					})
				}
				key = "~" + key
			} else {
				key, _ = generateKey(fixedLength)
			}
			var expireTime *time.Time // Process expire param
			if expiresString != "" {
				var err error
				if strings.HasPrefix(expiresString, "+") {
					expiresString = strings.Split(expiresString, "+")[1]
					var duration time.Duration
					duration, err = time.ParseDuration(expiresString)
					expiresAt := time.Now().Add(duration)
					expireTime = &expiresAt
				} else {
					var expiresAt time.Time
					expiresAt, err = time.Parse(time.RFC3339, expiresString)
					expireTime = &expiresAt
				}
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"code": http.StatusBadRequest,
						"msg":  "Error while parsing duration",
					})
					return
				}
			} else {
				expireTime = nil
			}

			// Insert into database
			for i := 0; i < 3; i++ {
				pasteContent := &model.PasteContent{
					Key:             key,
					Content:         uploadedContent,
					ContentType:     contentType,
					ContentLanguage: contentLanguage,
					ValidTill:       expireTime,
					Password:        contentPassword,
					UserId:          user.ID,
				}
				err := db.Create(&pasteContent).Error
				if err != nil {
					if strings.HasPrefix(key, "~") {
						c.JSON(http.StatusBadRequest, gin.H{
							"code": http.StatusBadRequest,
							"msg":  fmt.Sprintf("Failed to create with certain key %s, with error %s", key, err),
						})
						return
					} else {
						key, _ = generateKey(fixedLength)
					}
				} else {
					log.Printf("Created content with key: %s", key)
					c.JSON(http.StatusOK, gin.H{
						"code": http.StatusOK,
						"msg":  "Successfully created",
						"link": fmt.Sprintf("%sr/%s", baseDomain, key), // TODO: Using URL struct
					})
					return
				}
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"code": http.StatusInternalServerError,
				"msg":  fmt.Sprintf("Failed to create certain paste, please try again."),
			})
			return
		})
		// Check if key is used
		authorized.GET("/a/check/:key", func(c *gin.Context) {
			type ReqParam struct {
				Key string `uri:"key" binding:"required"`
			}
			var reqParam ReqParam
			if err := c.ShouldBindUri(&reqParam); err != nil {
				c.JSON(http.StatusNotAcceptable, gin.H{
					"code": http.StatusNotAcceptable,
					"msg":  err,
				})
				return
			}
			if !checkKeyExist(reqParam.Key, db) {
				c.JSON(http.StatusNotFound, gin.H{
					"code": http.StatusNotFound,
					"msg":  "Certain key " + reqParam.Key + " existed.",
				})
				return
			} else {
				c.JSON(http.StatusOK, gin.H{
					"code": http.StatusOK,
					"msg":  "Certain key " + reqParam.Key + " not existed.",
				})
				return
			}
		})
	}

	auth := r.Group("/a/auth")
	auth.Use(authMiddleware.MiddlewareFunc())
	{
		// Refresh time can be longer than token timeout
		auth.GET("/refresh_token", authMiddleware.RefreshHandler)
		auth.GET("/check", func(c *gin.Context) {
			claims := jwt.ExtractClaims(c)
			c.JSON(http.StatusOK, gin.H{
				"code":     http.StatusOK,
				"username": claims[identityKey],
			})
		})
	}

	err := r.Run()
	if err != nil {
		panic(err)
	}
}
