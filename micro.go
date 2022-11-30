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
	// Key  int64  `json:"key"`
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

	m := jsonEnregistrement{"h"}
	jsonValue, _ := json.Marshal(m)
	repPost, err := http.Post("https://jch.irif.fr:8443/register", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(repPost.StatusCode)

	//connexion
	//username
	userbyte := []byte("h")
	for i := 0; i < len(message); i++ {
		bufE := make([]byte, 14) //1é + 1 pour usename
		bufE[0] = 1
		bufE[1] = 2
		bufE[2] = 3
		bufE[3] = 4
		bufE[4] = 0 // type 0
		bufE[5] = 0
		bufE[6] = 0 //length
		bufE[7] = 0
		bufE[8] = 0 //flags
		bufE[9] = 0 //flag count d
		bufE[10] = 0
		bufE[11] = 0
		bufE[12] = 1           //user length
		bufE[13] = userbyte[0] //username

		addrconn := fmt.Sprintf("%s:%d", message[i].Host, message[i].Port)
		if debug {
			fmt.Printf("%s\n", addrconn)
		}
		// adr1, err := net.ResolveUDPAddr("udp", addrconn)
		// conn, err := net.ListenUDP("udp", adr1)
		conn, err := net.ListenPacket("udp", addrconn)
		if err != nil {
			log.Fatal(err)
		}
		n, err := conn.WriteTo(bufE, conn.LocalAddr())
		if err != nil {
			log.Fatal(err)
		}

		if debug {
			fmt.Println(n)
		}

		bufR := make([]byte, 256)

		n, ad, err := conn.ReadFrom(bufR)
		if err != nil {
			log.Fatal(err)
		}
		if debug {
			fmt.Println(n)
			fmt.Println(ad)
		}

	}

}

func main() {
	appelip()
}
