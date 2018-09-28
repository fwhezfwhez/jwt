package jwt

import (
	"testing"
	"strconv"
	"time"
	"fmt"
	//"container/list"
)

func TestGetRegister(t *testing.T) {
	register := GetRegister(10)
	t.Log(register)
}

func TestTokenRegister_Register(t *testing.T) {
	register := GetRegister(10)
	exp := time.Now().Add(1*time.Hour).Unix()
	register.Token.AddPayLoad("exp",strconv.FormatInt(exp,10)).AddPayLoad("userName","ft")
	jwt,_,err := register.Token.JwtGenerator("hello")
	if err!=nil{
		t.Fatal(err)
	}
	fmt.Println("生成的jwt是:",jwt)
	register.Register(jwt,exp,"ft")
}

func TestTokenRegister_Observe(t *testing.T) {
	register := GetRegister(10)
	register.Observe()
	var c  = make(chan int)
	<-c
}
