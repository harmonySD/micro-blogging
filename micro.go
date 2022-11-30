package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var debug = true
var idMess = 0

type jsonMessage struct {
	Host string `json:"ip"`
	Port int64  `json:"port"`
}

type jsonEnregistrement struct {
	Name string `json:"name"`
	// Key  int64  `json:"key"`
}

func rempMess(username string, typMess int) []byte {
	userbyte := []byte(username)
	userlength := len(userbyte)

	// //id+type+length+flag+flagcontd+usernamelength+username
	// //ATTENTION MANQUE SIGNATURE
	buflen := 4 + 1 + 2 + 1 + 3 + 1 + userlength
	buf := make([]byte, buflen)

	// //generation id
	idMess += 1
	idMessbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(idMessbyte, uint32(idMess))
	var i int
	k := 0
	for i = 0; i < 4; i++ {
		buf[i] = idMessbyte[k]
		k++
	}
	j := i
	buf[i] = byte(typMess)
	i++
	//5 -> flags (1) flagscontd(3) usernamelength(1)
	//ATTENTION MANQUE SIGNATURE
	lenght := 5 + userlength
	lenghtbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenghtbyte, uint16(lenght))
	j = i
	k = 0
	for i < j+2 {
		buf[i] = lenghtbyte[k]
		i++
		k++
	}
	//FLags et flags contd
	j = i
	k = 0
	for i < j+4 {
		buf[i] = 0
		i++
		k++
	}
	buf[i] = byte(userlength)
	i++
	j = i
	k = 0
	for i < j+userlength {
		buf[i] = userbyte[k]
		i++
		k++
	}
	if debug {
		fmt.Println("le mess dans rempMEss ", buf)
	}
	return buf
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
	//userbyte := []byte("h")

	for i := 0; i < len(message); i++ {
		bufE := rempMess("i", 0)
		if debug {
			fmt.Println("le mess dans bufE ", bufE)
		}

		// bufE := make([]byte, 14) //1é + 1 pour usename
		// bufE[0] = 0
		// bufE[1] = 0
		// bufE[2] = 0
		// bufE[3] = 1
		// bufE[4] = 0 // type 0
		// bufE[5] = 0
		// bufE[6] = 6 //length
		// bufE[7] = 0
		// bufE[8] = 0 //flags
		// bufE[9] = 0 //flag count d
		// bufE[10] = 0
		// bufE[11] = 1
		// bufE[12] = userbyte[0] //username
		fmt.Println(bufE)

		addrconn := fmt.Sprintf("%v:%v", message[i].Host, message[i].Port)
		port := fmt.Sprintf(":%d", message[i].Port)
		if debug {
			fmt.Printf("%s\n", addrconn)
		}
		// adr1, err := net.ResolveUDPAddr("udp", addrconn)
		// conn, err := net.ListenUDP("udp", adr1)
		conn, err := net.ListenPacket("udp", port)
		if err != nil {
			fmt.Printf("listen\n")
			log.Fatal(err)
		}
		// defer conn.Close() peut etre inutile
		//enfaite juste envoyer les writeto et rcvfom avec soit adress ipv6 ou adress ipv4

		dst, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			log.Fatal(err)
		}
		n, err := conn.WriteTo(bufE, dst)
		if err != nil {
			fmt.Printf("write\n")
			log.Fatal(err)
		}

		if debug {
			fmt.Println(n)
		}

		bufR := make([]byte, 256)

		n, _, err = conn.ReadFrom(bufR)
		if err != nil {
			fmt.Printf("read\n")
			log.Fatal(err)
		}
		if debug {
			fmt.Println(n)
			fmt.Println(bufR)
		}

	}

}

func main() {
	appelip()
}
