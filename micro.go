package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
)

var debug = true
var debugF = false // fonction remplMess
var debugP = false // fonction recherche de pair
var debugH = true  // fonction hello et helloReply
var idMess = 0

type jsonMessage struct {
	Host string `json:"ip"`
	Port int64  `json:"port"`
}

type jsonEnregistrement struct {
	Name string `json:"name"`
	Key  []byte `json:"key"`
}
type jsonPeer struct {
	Name     string        `json:"name"`
	Addresse []jsonMessage `json:"addresses"`
	Key      string        `json:"key"`
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

// fonction qui envoie un helloreply apres avoir recu un hello
func helloreply(addr net.Addr, bufR []byte) {
	fmt.Printf("hello\n")
	if debugH {
		fmt.Println("le mess dans bufR ", bufR)
	}
	bufE := rempMess("", 128)
	if debug {
		fmt.Println("le mess dans bufE ", bufE)
	}
	address := addr.String()
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	defer conn.Close()

	adr2, err := net.ResolveUDPAddr("udp", address)
	_, err = conn.WriteTo(bufE, adr2)
	if err != nil {
		fmt.Printf("write\n")
		log.Fatal(err)
	}
	if debug {
		fmt.Printf("helloReply envoye\n")
	}
}

// fonction qui envoie un hello et attend un helloreply
func hello(name string, pair string) {
	pairJson := chercherPair(pair)

	fmt.Printf("hello\n")
	addrconn := fmt.Sprintf("[%s]:%d", pairJson.Addresse[0].Host, pairJson.Addresse[0].Port)
	conn, err := net.ListenPacket("udp", addrconn)
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	defer conn.Close()

	bufE := rempMess(name, 0)
	adr2, err := net.ResolveUDPAddr("udp", addrconn)
	_, err = conn.WriteTo(bufE, adr2)
	if err != nil {
		fmt.Printf("write\n")
		log.Fatal(err)
	}
	if debug {
		fmt.Printf("hello envoye\n")
	}

	i := 1
	for i == 1 {
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
			i = 0
		}
		if bufR[4] == 254 {
			fmt.Printf("erreur\n")
			fmt.Println(string(bufR[7:]))
			i = 0
		}
	}

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
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey, _ := privateKey.Public().(*ecdsa.PublicKey)
	formatted := make([]byte, 64)
	publicKey.X.FillBytes(formatted[:32])
	publicKey.Y.FillBytes(formatted[32:])

	fmt.Printf("key : %d  %s \n\n", formatted, string(formatted))
	// var key int64 = 0
	m := jsonEnregistrement{name, formatted}
	jsonValue, err := json.Marshal(m)
	if err != nil {
		fmt.Printf("marshal\n")
		log.Fatal(err)
	}
	fmt.Println(m)
	fmt.Println(jsonValue)
	repPost, err := http.Post("https://jch.irif.fr:8443/register", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(repPost.StatusCode)
	if repPost.StatusCode != 204 {
		fmt.Printf("status\n")
		log.Fatal("status")
	}

	bufE := rempMess(name, 0)
	if debug {
		fmt.Println("le mess dans bufE ", bufE)
		fmt.Println(string(bufE[7:]))
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
	defer conn.Close() // peut etre inutile
	//enfaite juste envoyer les writeto et rcvfom avec soit adress ipv6 ou adress ipv4
	for i := 0; i < len(message)-1; i++ {
		fmt.Printf("\n\ndebut boucle\n")
		addrconn := fmt.Sprintf("[%s]:%d", message[i].Host, message[i].Port)
		// adr3 := &net.UDPAddr{
		// 	IP:   net.IP(message[i].Host),
		// 	Port: int(message[i].Port)}
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve\n")
			log.Fatal(err)
		}
		if debug {
			fmt.Printf("addrconn %s \n", addrconn)
			fmt.Printf("addrconn2 %s \n", adr2)
			// fmt.Printf("addrconn3 %s \n", adr3)
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
			// fmt.Printf("\n\n\nwhile\n")
			fmt.Printf("\n\n\n")
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

	// for {
	// 	bufR := make([]byte, 256)
	// 	_, addr, err := conn.ReadFrom(bufR)
	// 	if err != nil {
	// 		fmt.Printf("read\n")
	// 		log.Fatal(err)
	// 	}
	// 	switch bufR[4] {
	// 	case 0: // hello
	// 		helloreply(addr, bufR)

	// 	// case 128: // helloreply

	// 	case 1: // root

	// 	// case 129: //rootreply

	// 	case 2: // getdatum

	// 	// case 131: // nodatum

	// 	// case 130: // datum

	// 	case 254: //erreur
	// 		fmt.Printf("erreur\n")
	// 		fmt.Println(string(bufR[7:]))
	// 		// break
	// 	default:
	// 		break
	// 	}
	// }

}

func chercherPairs() string {
	resp, err := http.Get("https://jch.irif.fr:8443/peers")
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	if debugP {
		fmt.Printf("%s\n", string(body))
	}
	liste := string(body)
	return liste
}
func chercherPair(username string) jsonPeer {
	addr := fmt.Sprintf("https://jch.irif.fr:8443/peers/%s", username)
	resp, err := http.Get(addr)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)

	var message jsonPeer
	err = json.Unmarshal([]byte(body), &message)
	if err != nil {
		log.Fatal(err)
	}

	if debugP {
		fmt.Printf("name : %s \n", message.Name)
		for i := 0; i < len(message.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", message.Addresse[i].Host, message.Addresse[i].Port)

		}
	}
	return message
}

func main() {
	appelip()
	fmt.Println()
	liste := chercherPairs()
	fmt.Printf("liste %s\n", liste)
	if liste != "" {
		pair := chercherPair("galene")
		fmt.Printf("name : %s \n", pair.Name)
		for i := 0; i < len(pair.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)

		}
	}

}
