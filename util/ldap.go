package util

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/ldap.v3"
)

const (
	ldapServer       = "localhost:389"
	ldapBindDn       = "cn=binding,ou=config,dc=xxx,dc=yyy,dc=zzz"
	ldapBindPassword = "xxx"
	BaseDN           = "dc=xxx,dc=yyy,dc=zzz"
)

func LdapConnect() *ldap.Conn {
	conn, err := ldap.Dial("tcp", ldapServer)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	return conn
}

func LdapBind(conn *ldap.Conn) {
	err := conn.Bind(ldapBindDn, ldapBindPassword)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func LdapAuthen(conn *ldap.Conn, username string, password string) bool {
	isValid, err := conn.Compare(fmt.Sprintf("cn=%s,ou=staff,dc=xxx,dc=yyy,dc=zzz", username), "userPassword", PlainPasswordToLdapSha256(password))
	if err != nil {
		fmt.Println(err)
		return false
	}

	return isValid
}

func PlainPasswordToLdapSha256(plainPassword string) string {
	sha256PasswordBytes := sha256.Sum256([]byte(plainPassword))
	sha256Password := base64.StdEncoding.EncodeToString(sha256PasswordBytes[0:len(sha256PasswordBytes)])
	return fmt.Sprintf("{SHA256}%s", string(sha256Password))
}

func GetPersonGroup(conn *ldap.Conn, username string) (members []string) {
	result, err := conn.Search(ldap.NewSearchRequest(
		BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(cn=%s)", username),
		[]string{"member"},
		nil,
	))

	if err != nil {
		fmt.Println(err)
		return
	}

	if len(result.Entries) != 1 {
		fmt.Println("Found more than 1 person, username (cn) should be unique!")
		return
	}

	entry := result.Entries[0]
	groups := entry.GetAttributeValues("member")
	cnRegxp, _ := regexp.Compile("cn=([a-z1-9]+),")
	for _, groupDn := range groups {
		groupCn := cnRegxp.FindStringSubmatch(groupDn)
		if len(groupCn) > 0 {
			members = append(members, groupCn[1])
		}
	}

	return
}
