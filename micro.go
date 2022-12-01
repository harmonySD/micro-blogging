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
var debugF = false
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
	if debugF {
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

	name := "sarah"
	m := jsonEnregistrement{name}
	jsonValue, _ := json.Marshal(m)
	repPost, err := http.Post("https://jch.irif.fr:8443/register", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(repPost.StatusCode)

	bufE := rempMess(name, 0)
	if debug {
		fmt.Println("le mess dans bufE ", bufE)
	}

	port := fmt.Sprintf(":%d", message[0].Port)
	if debug {
		fmt.Printf("port : %s\n", port)
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
	for i := 0; i < len(message)-1; i++ {
		fmt.Printf("\n\ndebut boucle\n")
		addrconn := fmt.Sprintf("%s:%d", message[i].Host, message[i].Port)
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if debug {
			fmt.Printf("addrconn %s \n", addrconn)
		}

		_, err = conn.WriteTo(bufE, adr2)
		if err != nil {
			fmt.Printf("write\n")
			log.Fatal(err)
		}
		if debug {
			// fmt.Printf("write\n")
			fmt.Printf("hello envoye\n")
		}

		for {
			fmt.Printf("\n\n\nwhile\n")
			bufR := make([]byte, 256)

			_, _, err = conn.ReadFrom(bufR)
			if err != nil {
				fmt.Printf("read\n")
				log.Fatal(err)
			}
			if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
				fmt.Printf("helloReply\n")
				if debug {
					fmt.Println("le mess dans bufR ", bufR)
				}
			}
			if bufR[4] == 0 {
				fmt.Printf("hello\n")
				if debug {
					fmt.Println("le mess dans bufR ", bufR)
				}
				bufE := rempMess("", 128)
				if debug {
					fmt.Println("le mess dans bufE ", bufE)
				}
				_, err = conn.WriteTo(bufE, adr2)
				if err != nil {
					fmt.Printf("write\n")
					log.Fatal(err)
				}
				if debug {
					fmt.Printf("helloReply envoye\n")
				}
				break
			}
			if bufR[4] == 254 {
				fmt.Printf("erreur\n")
				fmt.Println(string(bufR[7:]))
				break
			}
		}
		defer conn.Close()
	}

}

func main() {
	appelip()

}
