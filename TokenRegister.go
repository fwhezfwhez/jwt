package jwt

import (
	"container/list"
	"github.com/pkg/errors"
	"time"
	"fmt"
)

type JWT struct {
	Jwt string
	Exp int64
}

type TokenRegister struct {
	Token *Token //only use its Decode()

	MemoryRegister    *list.List               //内存管理器，功能仿redis，性能更高效  memory redis alike however faster and more efficient
	RegisterMemoryMap map[string]*list.Element //由于List在擦除时操作的对象是*Element而非interface{},所以需要该map来索引
	//a map that helps to index to remove an interface{}
	MaxSize int //controls the max size of memoryRegister and registerMemoryMap
}

//Get TokenRegister instance with maxSize more than 2000 and alloc space for its components
func GetRegister(maxSize int) *TokenRegister {

	tokenRegister := &TokenRegister{}
	tokenRegister.Token = GetToken()
	tokenRegister.MemoryRegister = list.New()
	tokenRegister.RegisterMemoryMap = make(map[string]*list.Element)
	if maxSize < 1000 {
		maxSize = 2000
	}
	tokenRegister.MaxSize = maxSize
	return tokenRegister
}

func (tokenRegister *TokenRegister) SetMaxSize(maxSize int) {
	tokenRegister.MaxSize = maxSize
}

//Register a jwt with Unix time expire time exp and unique mapKey like 'userName'
//Assume you have get a jwt block from generator or from a request header
//make sure token instance from GetToken() or some components may not get alloc yet
//mapKey is a key of RegisterMemoryMap that indexes the element in registerList,for example an unique key like userName is advised to be a mapKey
//example is in MemeryRegister_test
func (tokenRegister *TokenRegister) Register(jwt string, exp int64, mapKey string) {
	jwtStruct := JWT{}
	jwtStruct.Jwt = jwt
	if exp < time.Now().Unix() {
		exp = time.Now().Add(1 * time.Hour).Unix()
	}
	jwtStruct.Exp = exp
	elem := tokenRegister.MemoryRegister.PushBack(jwtStruct)
	tokenRegister.RegisterMemoryMap[mapKey] = elem
	fmt.Println("登记成功")
}

//Remove a jwt
func (tokenRegister *TokenRegister) Remove(jwt string, mapKey string) error {
	p, _, _, err := tokenRegister.Token.Decode(jwt)
	if err != nil {
		return err
	}
	if mapKey == "" {
		if v, ok := p["userName"]; ok {
			mapKey = v
		} else {
			return errors.New("cannot find corret mapKey,have you register it in map as mapKey or is payload containing key'userName'?")
		}
	}
	tokenRegister.MemoryRegister.Remove(tokenRegister.RegisterMemoryMap[mapKey])
	delete(tokenRegister.RegisterMemoryMap, mapKey)
	return nil
}

//Observe used in en environment that keeps running or it may risk skipping
func (tokenRegister *TokenRegister) Observe() {
	//开启管理
	fmt.Println("开启管理Register")
	go func() {
		for {
			//管理大小
			if tokenRegister.MemoryRegister.Len() == tokenRegister.MaxSize {
				tokenRegister.MemoryRegister = list.New()
			}
			//管理时效
			if tokenRegister.MemoryRegister.Len() != 0 {
				nowUnix := time.Now().Unix()
				frontElem := tokenRegister.MemoryRegister.Front()
				elemTemp :=frontElem.Value.(JWT)
				endUnix := elemTemp.Exp
				jwt:=elemTemp.Jwt

				if nowUnix > endUnix {
					//过期了
					tokenRegister.MemoryRegister.Remove(frontElem)
					delete(tokenRegister.RegisterMemoryMap,jwt)
				}
			}
			//防止抱死时间片不放
			time.Sleep(10 * time.Minute)
		}
	}()
}
