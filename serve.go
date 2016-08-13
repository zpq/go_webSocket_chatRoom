package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/websocket"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	users           map[string]*User
	clients         map[string]*websocket.Conn
	refreshUserList chan bool
)

var tokenSecret string = "XCROOM"

var addr = flag.String("addr", "localhost:8018", "http service address")

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type User struct {
	Name      string `json:"name"`
	LastAlive int64  `json:"lastAlive"`
	IsOnline  bool   `json:"isOnLine"`
}

type Message struct {
	Content string `json:"content"`
}

type Response struct {
	Status  int           `json:"status"`
	Message string        `json:"message"`
	Data    []interface{} `json:"data"`
}

type AssignTemp struct {
	Url      string
	Username string
	IsLogin  int
}

//delete
func GcOfflineUser() {

}

func refreshUserListsHandle() {
	for {
		refresh := <-refreshUserList
		if refresh {
			res := Response{2, "refresh Userlists", nil}
			for _, v := range users {
				if v.IsOnline {
					res.Data = append(res.Data, v)
				}
			}
			log.Println("len clients=", len(clients))
			for _, v := range clients {
				v.WriteJSON(res)
			}
		}
	}
}

func Ws(w http.ResponseWriter, r *http.Request) {
	var isNew bool
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error : " + err.Error())
	}
	c1, err1 := r.Cookie("username")
	c2, err2 := r.Cookie("x-token")
	if err1 != nil || err2 != nil { // close connection
		log.Println(err1.Error() + " ~~ " + err2.Error())
		return
	}

	username, token := c1.Value, c2.Value
	defer func() {
		log.Println("user leave")
		delete(clients, token) // important
		_, ok := users[token]
		if ok {
			users[token].IsOnline = false
		}
		refreshUserList <- true
		log.Println("close conn")
		conn.Close()
	}()

	for {
		//check token
		tc, err := checkToken(token)
		if err != nil {
			log.Println(err.Error())
			break
		}
		t := tc["username"].(string) // type transfer [interface{} => string]
		if t != username {
			log.Println("username not equal between token and cookie")
			break
		}

		_, ok := users[token]
		if !ok {
			log.Println("invalid user")
			break
		}

		_, ok = clients[token]
		if !ok { //用户刚刚上线
			clients[token] = conn
			users[token].IsOnline = true
			users[token].LastAlive = time.Now().Unix()
			isNew = true
			refreshUserList <- true
		} else {
			isNew = false
		}
		_, content, err := conn.ReadMessage()
		if err != nil {
			log.Println("read mesage error : " + err.Error())
			break
		}
		var writeMessage string
		if isNew {
			writeMessage = username + " enter the room! "
		} else {
			writeMessage = username + " says: " + string(content)
		}
		msg := Message{writeMessage}
		res := Response{1, "send message success", nil}
		res.Data = append(res.Data, msg)
		for _, v := range clients {
			log.Println("broadcast")
			err = v.WriteJSON(res)
			if err != nil {
				log.Println("send error :" + err.Error())
				return
			}
		}
	}
}

func read(conn *websocket.Conn) {

}

func write(conn *websocket.Conn) {

}

func broadcast() {

}

func Home(w http.ResponseWriter, r *http.Request) {
	t, err := template.ParseFiles("./index.html")
	if err != nil {
		log.Fatal(err.Error())
	}
	temp := AssignTemp{"ws://" + r.Host + "/ws", "", 0}
	c1, err1 := r.Cookie("username")
	c2, err2 := r.Cookie("x-token")
	if err1 != nil || err2 != nil {
		log.Println("cookie template :", err1.Error(), "~~", err2.Error())
	} else {
		tc, err := checkToken(c2.Value)
		if err != nil {
			log.Println(err.Error())
		} else {
			username := strings.Trim(c1.Value, "")
			t := tc["username"].(string)
			if username != "" && t == username {
				temp.Username = username
				temp.IsLogin = 1
			} else {
				log.Println("username in token does not equal username in cookie")
			}
		}
	}
	t.Execute(w, temp)
}

func Login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := strings.Trim(r.PostFormValue("username"), "")
	res := Response{0, "username empty", nil}
	if username != "" {
		_, ok := users[username]
		if !ok {
			log.Println("username not exists")
			token, err := createToken(username)
			if err != nil {
				log.Println(err.Error())
				res.Message = "create token failed"
			} else {
				expiration := time.Now()
				expiration = expiration.AddDate(365, 0, 0)
				cookie := http.Cookie{Name: "x-token", Value: token, Expires: expiration, HttpOnly: true}
				http.SetCookie(w, &cookie)
				cookie = http.Cookie{Name: "username", Value: username, Expires: expiration, HttpOnly: true}
				http.SetCookie(w, &cookie)
				users[token] = &User{username, time.Now().Unix(), false}
				res.Data = append(res.Data, users[token])
				res.Status = 1
				res.Message = "login success"
				refreshUserList <- true
			}
		} else {
			log.Println("username exists")
			c, err := r.Cookie("token")
			if err != nil {
				res.Message = "token empty"
			} else {
				token := c.Value
				tc, err := checkToken(token)
				if err != nil {
					res.Message = "Invalid token"
				} else {
					if tc["username"] != username {
						res.Message = "invalid username or this username already exists"
					} else {
						res.Data = append(res.Data, users[token])
						res.Status = 1
						res.Message = "login success"
						refreshUserList <- true
					}
				}
			}
		}
	}
	body, _ := json.Marshal(res)
	w.Write([]byte(body))
}

func createToken(username string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username,
		"nbf":      time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})
	return token.SignedString([]byte(tokenSecret))
}

func checkToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func main() {
	users = make(map[string]*User)
	clients = make(map[string]*websocket.Conn)
	refreshUserList = make(chan bool)
	go refreshUserListsHandle() //人多可以多开几个线程
	http.HandleFunc("/", Home)
	http.HandleFunc("/login", Login)
	http.HandleFunc("/ws", Ws)
	http.ListenAndServe(*addr, nil)
}
