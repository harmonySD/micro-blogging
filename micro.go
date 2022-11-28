package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var debug = true

type jsonMessage struct {
	Host string `json:"ip"`
	Port int64  `json:"port"`
}

type jsonEnregistrement struct {
	Name string `json:"name"`
	Key  int64  `json:"key"`
}

func appelip() {
	resp, err := http.Get("https://jch.irif.fr:8443/udp-address")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var message []jsonMessage
	err = json.Unmarshal([]byte(body), &message)
	if err != nil {
		log.Fatal(err)
	}

	if debug {
		for i := 0; i < len(message); i++ {
			fmt.Printf("ip : %s \n port: %d\n", message[i].Host, message[i].Port)
		}
	}

	//envoie post
	m := jsonEnregistrement{"harmo", 0}
	jsonValue, _ := json.Marshal(m)
	repPost, err := http.Post("https://jch.irif.fr:8443/register", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	if debug {
		// var res map[string]interface{}
		// json.NewDecoder(repPost.Body).Decode(&res)
		// fmt.Println(res["json"])
		fmt.Println(repPost)
	}

	//connexion
	for i := 0; i < len(message); i++ {
		addrconn := fmt.Sprintf("%s:%d", message[i].Host, message[i].Port)
		conn, err := net.Dial("udp", addrconn)
		if err != nil {
			log.Fatal(err)
		}

	}

}

func main() {
	appelip()
}
