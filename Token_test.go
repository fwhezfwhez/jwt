package jwt

import (
	"testing"
	"time"
	"strconv"
)
func TestToken_JwtGenerator(t *testing.T) {
	token := GetToken()
	token.AddHeader("typ", "JWT").AddHeader("alg", "HS256")
	exp,err2 := time.Parse("2006-01-02 15:04:05","2018-03-19 9:55:44")
	token.AddPayLoad("exp",strconv.FormatInt(exp.Unix(),10))
	if err2!=nil{
		t.Fatal(err2)
	}

	token.AddPayLoad("userName", "admin").AddPayLoad("role", "admin")
	jwt, _, err := token.JwtGenerator("hello")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("签名是:",jwt)
}

func TestToken_Decode(t *testing.T) {
	token := GetToken()
	p, h, hs, err := token.Decode("eyJleHAiOiIxNTIxNDUzMzQ0Iiwicm9sZSI6ImFkbWluIiwidXNlck5hbWUiOiJhZG1pbiJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.5t2Bw6wCjKz+8zlOFJ3UIuEOBPBZL4/N0nDOnYtGnso=")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("解出的payload:",p)
	t.Log("解出的header",h)
	t.Log("截出的HS256段",hs)
}

func TestToken_IsLegal(t *testing.T) {
	token := GetToken()
	legal, err := token.IsLegal("eyJleHAiOiIxNTIxNDUzMzQ0Iiwicm9sZSI6ImFkbWluIiwidXNlck5hbWUiOiJhZG1pbiJ9.eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.5t2Bw6wCjKz+8zlOFJ3UIuEOBPBZL4/N0nDOnYtGnso=", "hello")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("是否合法：",legal)
}

