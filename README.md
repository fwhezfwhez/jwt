JWT(JAVA WEB TOKEN)
<p>
目前只支持HS256加密！
</p>
Example:
```go
package main

import (
	"github.com/fwhezfwhez/jwt"
	"fmt"
	"time"
	"strconv"
)

func main(){
	var secret ="Example Secret Key"
	//获取jwt令牌
	token :=jwt.GetToken()
	token.AddHeader("typ", "JWT").AddHeader("alg", "HS256")
	exp,err := time.Parse("2006-01-02 15:04:05","2018-03-20 10:59:44")
	if err!=nil {
		fmt.Println(err)
		return
	}
	token.AddPayLoad("exp",strconv.FormatInt(exp.Unix(),10))
	jwt,_,err:=token.JwtGenerator(secret)
	fmt.Println("签名是:",jwt)

	//解码jwt令牌
	p,h,hs,err := token.Decode(jwt)
	if err!=nil {
		fmt.Println(err)
		return
	}
	fmt.Println("payLoad:",p)
	fmt.Println("header:",h)
	fmt.Println("hs256String:",hs)

	//判断令牌有效性
	valide,err:=token.IsLegal(jwt,secret)
	if err!=nil {
		fmt.Println(err)
		return
	}
	if valide ==true {
		fmt.Println("令牌正确")
		return
	}
	fmt.Println("令牌错误或过期")

}

```