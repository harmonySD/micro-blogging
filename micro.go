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
	// Key  []byte `json:"key"`
}
type jsonPeer struct {
	Name     string        `json:"name"`
	Addresse []jsonMessage `json:"addresses"`
	Key      string        `json:"key"`
}

func rempMess(username string, typMess int, bufR []byte) []byte {
	userbyte := []byte(username)
	userlength := len(userbyte)

	// //id+type+length+flag+flagcontd+usernamelength+username
	// //ATTENTION MANQUE SIGNATURE
	buflen := 4 + 1 + 2 + 1 + 3 + 1 + userlength
	buf := make([]byte, buflen)

	var i int
	if typMess == 0 {
		// //generation id
		idMess += 1
		idMessbyte := make([]byte, 4)
		binary.BigEndian.PutUint32(idMessbyte, uint32(idMess))
		for i = 0; i < 4; i++ {
			buf[i] = idMessbyte[i]
		}
	} else if typMess == 128 {
		for i = 0; i < 4; i++ {
			buf[i] = bufR[i]
		}
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
	k := 0
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
	//username length
	buf[i] = byte(userlength)
	i++
	//username
	j = i
	k = 0
	for i < j+userlength {
		buf[i] = userbyte[k]
		i++
		k++
	}
	//continueer avec la key
	if debugF {
		fmt.Println("le mess dans rempMEss ", buf)
	}
	return buf
}

// fonction qui envoie un helloreply apres avoir recu un hello
func helloreply(adr net.Addr, bufR []byte, nameM string, conn net.PacketConn) {
	if debugH {
		fmt.Printf("hello\n")
		fmt.Println("le mess dans bufR ", bufR)
	}
	//remplir pour un message avec NOTRE id type 128 et le bufrecu du hello
	bufE := rempMess(nameM, 128, bufR)
	if debug {
		fmt.Println("le mess dans bufE ", bufE)
	}
	//envoie de bufE aka le message helloreply
	address := adr.String()
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
// si forServeur ==1 cets quon est dan sle cas handshake serveur
func handshake(name string, addrconn string, conn net.PacketConn, forServeur int) {
	if debugH {
		fmt.Printf("hello\n")
	}
	addr2, err := net.ResolveUDPAddr("udp", addrconn)
	if err != nil {
		fmt.Printf("resolve\n")
		log.Fatal(err)
	}
	if debugH {
		fmt.Printf("addrconn %s \n", addrconn)
		fmt.Printf("addrconn2 %s \n ", addr2)
	}
	//preparation message bufE ENVOYE HELLO
	buf := make([]byte, 1)
	bufE := rempMess(name, 0, buf)
	if debugH {
		fmt.Println("le mess dans bufE ", bufE)
		fmt.Println(string(bufE[7:]))
	}
	_, err = conn.WriteTo(bufE, addr2)
	if err != nil {
		fmt.Printf("write\n")
		log.Fatal(err)
	}
	if debugH {
		fmt.Printf("hello envoye !\n")
	}
	//attente du helloreply ATTENTION GERER RTT
	brk1 := 0
	brk2 := 0
	for brk1 != 1 || brk2 != 1 {
		if debugH {
			fmt.Printf("\n\n\n")
		}
		//prepare bufrecevoir pour ecrire le message recu dedans
		bufR := make([]byte, 256)
		_, _, err = conn.ReadFrom(bufR)
		if err != nil {
			fmt.Printf("read\n")
			log.Fatal(err)
		}
		//verif que cest bien un helloreply (donc type 128) et id du hello = id du helloreply
		if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
			if debugH {
				fmt.Printf("helloreply\n")
				fmt.Println("le mess dasn bufR ", bufR)
				brk1 += 1
				//si forServeur ==1 cets quon est dan sle cas handshake serveur
				if forServeur != 1 {
					brk2 += 1
				}
			}
		}
		if bufR[4] == 254 {
			if debugH {
				fmt.Printf("erreur\n")
				fmt.Println(string(bufR[7:]))
			}
		}
		if bufR[4] == 0 {
			helloreply(addr2, bufR, name, conn)
			brk2 += 1
		}
		if brk1 > 2 || brk2 > 2 {
			fmt.Printf("PROBLEME HANDSHAKE\n")
		}
	}
}

func appelip() {
	// recherche adresse du serveur
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

	// enregistrement dans le serveur
	name := "sarah"
	// privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// publicKey, _ := privateKey.Public().(*ecdsa.PublicKey)
	// formatted := make([]byte, 64)
	// publicKey.X.FillBytes(formatted[:32])
	// publicKey.Y.FillBytes(formatted[32:])

	// fmt.Printf("key : %d  %s \n\n", formatted, string(formatted))
	// var key int64 = 0

	//on s'enregistre sur le serveur
	m := jsonEnregistrement{Name: name}
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
	// ecoute sur port en udp
	port := ":4486"
	if debug {
		fmt.Printf("port : %s\n", port)
	}
	conn, err := net.ListenPacket("udp", port)
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	defer conn.Close() // peut etre inutile

	//handshake avec le serveur
	for i := 0; i < len(message)-1; i++ {
		fmt.Printf("\n\ndebut boucle\n")
		addrconn := fmt.Sprintf("[%s]:%d", message[i].Host, message[i].Port)
		//envoie hello et dedans appel helloreply si recoit hello du retour sort quand a recu le helloreply
		//du serveur plus envoyer hello reply au serveur
		//si forServeur ==1 cets quon est dan sle cas handshake serveur
		handshake(name, addrconn, conn, 1)
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
	// 		helloreply(addr, bufR, name, conn)

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
		pair := chercherPair("sarah")
		fmt.Printf("name : %s \n", pair.Name)
		for i := 0; i < len(pair.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)

		}
	}
	// hello("sarah", "Ju")

}
