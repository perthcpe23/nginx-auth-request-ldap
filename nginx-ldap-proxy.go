package main

import (
	"encoding/base64"
	"fmt"
	"nginx-auth-request-ldap/util"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

func returnUnauthoried(c *gin.Context) {
	c.Header("WWW-Authenticate", "Basic realm=\"Secure Area\"")
	c.String(401, "")
}

func main() {
	r := gin.Default()

	r.OPTIONS("/*request", func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-type")
	})

	r.GET("/*request", func(c *gin.Context) {
		// check for authen HTTP header
		if value, exist := c.Request.Header["Authorization"]; exist {
			checkAuthorizeGroup := "general" // default group
			headerGroups := c.Request.Header["X-Group"]
			if len(headerGroups) > 0 {
				checkAuthorizeGroup = headerGroups[0]
			}

			auth, _ := base64.StdEncoding.DecodeString(strings.Replace(value[0], "Basic ", "", -1))
			tmp := strings.Split(string(auth), ":")

			// user/pass from HTTP header
			username := tmp[0]
			password := tmp[1]

			conn := util.LdapConnect()
			defer conn.Close()
			util.LdapBind(conn)

			// authenticate
			isValid := util.LdapAuthen(conn, username, password)

			if isValid {
				groups := util.GetPersonGroup(conn, username)
				sort.Strings(groups)
				index := sort.SearchStrings(groups, checkAuthorizeGroup)

				// authorize
				if index < len(groups) && groups[index] == checkAuthorizeGroup {
					c.String(200, "Ok")
				} else {
					fmt.Println("Authenticated but unauthorized")
					returnUnauthoried(c)
				}
			} else {
				fmt.Println("Authenticate error")
				returnUnauthoried(c)
			}
		} else {
			fmt.Println("No authenicate header")
			returnUnauthoried(c)
		}
	})
	r.Run("0.0.0.0:9009")
}
