package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"
)

var debug = true
var debugF = false // fonction remplMesshello
var debugP = false // fonction recherche de pair
var debugH = true  // fonction hello et helloReply
var debugA = false // fonction arbre de Merkle
var debugRQ = true // fonction root request
var debugM = true  // fonction rempMess
var debugD = true  // fonction datum etc
var idMess = 0
var a arbreMerkle

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

// arbre de Merkle
type noeud struct {
	value  []byte
	gauche *noeud //left
	droit  *noeud //right
}
type arbreMerkle struct {
	racine *noeud
}

func initialisationArbre() {
	a.racine = nil
}
func ajoutMess(mess string, rep []byte) {
	message := rempMessArbre(mess, rep)
	if debugA {
		fmt.Println("\n\nmessage", message)
		fmt.Println()
	}
	nv := noeud{message, nil, nil}
	if a.racine == nil { // racine vide
		a.racine = &nv
	} else { // ajout message  normal
		hashNoeud := rempNoeudArbre(a.racine, &nv)
		rac := noeud{hashNoeud, a.racine, &nv}
		a.racine = &rac
	}
}

func affichageArbre() {
	affichageNoeud(a.racine)
	fmt.Printf("\n\n")
}
func affichageNoeud(n *noeud) {
	if n == nil {
		fmt.Printf("Vide\n")
	} else {
		if n.value[0] == 0 {
			// fmt.Println(n.value)
			fmt.Println(string(n.value[(1 + 4 + 32 + 2):]))

		} else {
			affichageNoeud(n.gauche)
			affichageNoeud(n.droit)
		}
	}

}

// https://tech-wiki.online/fr/golang-data-structure-binary-search-tree.html

func rempNoeudArbre(gauche *noeud, droit *noeud) []byte {
	lenNoeud := 1 + 32 + 32
	buf := make([]byte, lenNoeud)

	hg := sha256.Sum256(gauche.value)
	hd := sha256.Sum256(gauche.value)
	buf[0] = 1
	k := 32
	for i := 0; i < 32; i++ {
		buf[i+1] = hg[i]
		buf[i+1+k] = hd[i]
	}

	return buf
}

// mess : le message
// rep le hash du message auquel on repond, vide si pas de reponse
func rempMessArbre(mess string, rep []byte) []byte {
	messbyte := []byte(mess)
	messlength := len(messbyte)
	lenMess := 1 + 4 + 32 + 2 + messlength
	buf := make([]byte, lenMess)

	buf[0] = 0
	now := time.Now()
	janvier := time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)
	date := now.Sub(janvier)
	sec := date.Seconds()
	if debugA {
		fmt.Printf("date %v\nsec%v\n", date, sec)
	}
	secbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(secbyte, uint32(sec))
	k := 1
	for i := 0; i < 4; i++ {
		buf[i+k] = secbyte[i]
	}
	k += 4
	if len(rep) != 0 {
		for i := 0; i < 32; i++ {
			buf[i+k] = rep[i]
		}
	} else {
		for i := 0; i < 32; i++ {
			buf[i+k] = 0
		}
	}
	k += 32
	lenghtbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenghtbyte, uint16(messlength))
	for i := 0; i < 2; i++ {
		buf[i+k] = lenghtbyte[i]
	}
	k += 2
	for i := 0; i < messlength; i++ {
		buf[i+k] = messbyte[i]
	}
	if debugA {
		fmt.Println("Message arbre ", buf)
	}
	return buf
}
func rempMess(typMess int, length int) []byte {

	// //id+type+length+taillebody
	// //ATTENTION MANQUE SIGNATURE
	buflen := 4 + 1 + 2 + length
	buf := make([]byte, buflen)

	var i int
	// //generation id
	idMess += 1
	idMessbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(idMessbyte, uint32(idMess))
	for i = 0; i < 4; i++ {
		buf[i] = idMessbyte[i]
	}
	//type
	j := i
	buf[i] = byte(typMess)
	i++
	//length
	lenghtbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenghtbyte, uint16(length))
	j = i
	k := 0
	for i < j+2 {
		buf[i] = lenghtbyte[k]
		i++
		k++
	}
	// body
	if typMess == 129 { // cas root
		hracine := sha256.Sum256(a.racine.value)
		j = i
		k = 0
		for i < j+length {
			buf[i] = hracine[k]
			i++
			k++
		}
	} else if typMess == 1 { //cas root request
	}

	// continuer avec la key
	if debugM {
		fmt.Println("le mess dans rempMEss ", buf)
	}
	return buf
}

func rempMesshello(username string, typMess int, bufR []byte) []byte {
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
	// 5 -> flags (1) flagscontd(3) usernamelength(1)
	// ATTENTION MANQUE SIGNATURE
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
	// Flags et flags contd
	j = i
	k = 0
	for i < j+4 {
		buf[i] = 0
		i++
		k++
	}
	// username length
	buf[i] = byte(userlength)
	i++
	// username
	j = i
	k = 0
	for i < j+userlength {
		buf[i] = userbyte[k]
		i++
		k++
	}
	// continueer avec la key
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
	// remplir pour un message avec NOTRE id type 128 et le bufrecu du hello
	bufE := rempMesshello(nameM, 128, bufR)
	if debugH {
		fmt.Println("helloreply, le mess dans bufE ", bufE)
	}
	// envoie de bufE aka le message helloreply
	address := adr.String()
	adr2, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		fmt.Printf("resolveudp\n")
		log.Fatal(err)
	}
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
// si forServeur ==1 cets quon est dans le cas handshake serveur
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
		fmt.Printf("addrconn2 %s \n", addr2)
	}

	// attente du helloreply ATTENTION GERER RTT
	brk1 := 0
	brk2 := 0
	tps := 2
	for brk1 != 1 || brk2 != 1 {
		// preparation message bufE ENVOYE HELLO
		buf := make([]byte, 1)
		bufE := rempMesshello(name, 0, buf)
		if brk1 != 1 {
			if debugH {
				fmt.Println("le mess dans bufE ", bufE)
				fmt.Println("mess lisible ", string(bufE[7:]))
				fmt.Printf("addrconn2 %s \n", addr2)
			}
			_, err = conn.WriteTo(bufE, addr2)
			if err != nil {
				fmt.Printf("write\n")
				log.Fatal(err)
			}
			if debugH {
				fmt.Printf("hello envoye !\n")
			}
		}

		if debugH {
			fmt.Printf("\n\n\n")
		}
		// prepare bufrecevoir pour ecrire le message recu dedans
		bufR := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
		_, _, err = conn.ReadFrom(bufR)
		if err != nil {
			fmt.Printf("Attente\n")
			tps = tps * 2
			if tps >= 32 {
				tps = 2
			}
		}
		// verif que cest bien un helloreply (donc type 128) et id du hello = id du helloreply
		if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
			fmt.Printf("recu helloreply correct\n")
			if debugH {
				fmt.Println("le mess dans bufR ", bufR)
			}
			brk1 += 1
			// si forServeur == 1 cest quon est dans le cas handshake serveur
			if forServeur != 1 {
				brk2 += 1
			}
			tps = 2
		}
		if bufR[4] == 254 {
			if debugH {
				fmt.Printf("message erreur\n")
				fmt.Println(string(bufR[7:]))
			}
		} else if (bufR[4] == 0) && (bufR[6] != 0) { // hello recu
			helloreply(addr2, bufR, name, conn)
			brk2 += 1
		}
		if brk1 > 2 || brk2 > 2 {
			fmt.Printf("PROBLEME HANDSHAKE\n")
		}
	}
	//defer conn.Close()
}

func session(name string) net.PacketConn {
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
	// 49 152 à 65 535
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	limitPort := 65535 - 1024
	i := r.Intn(limitPort) + 1024
	port := fmt.Sprintf(":%d", i)
	if debug {
		fmt.Printf("port : %s\n", port)
	}
	conn, err := net.ListenPacket("udp", port)
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	//defer conn.Close()
	//handshake avec le serveur
	for i := 0; i < len(message)-1; i++ {
		fmt.Printf("\n\ndebut boucle\n")
		addrconn := fmt.Sprintf("[%s]:%d", message[i].Host, message[i].Port)
		//envoie hello et dedans appel helloreply si recoit hello du retour sort quand a recu le helloreply
		//du serveur plus envoyer hello reply au serveur
		//si forServeur ==1 cets quon est dan sle cas handshake serveur
		handshake(name, addrconn, conn, 1)
	}
	return conn
}

// demande de rootrequest
func rootrequestmess(adr string, conn net.PacketConn) {
	if debugRQ {
		fmt.Println("rootrequest please")
	}
	//envoie de bufE

	adr2, err := net.ResolveUDPAddr("udp", adr)
	if err != nil {
		fmt.Printf("resolve")
		log.Fatal(err)
	}
	tps := 2
	brk1 := 0
	for brk1 != 1 {
		bufE := rempMess(1, 0)
		if debugRQ {
			fmt.Println("root request mess : dans bufE ", bufE)
		}
		_, err = conn.WriteTo(bufE, adr2)
		if err != nil {
			fmt.Println("write")
			log.Fatal(err)
		}
		if debugRQ {
			fmt.Println("demande root request envoyer! ")
		}
		// prepare bufrecevoir pour ecrire le message recu dedans
		bufR := make([]byte, 256)
		conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
		_, _, err = conn.ReadFrom(bufR)
		if err != nil {
			fmt.Printf("Attente\n")
			tps = tps * 2
			if tps >= 32 {
				tps = 2
			}
		}
		// verif que cest bien un rootreply (donc type 129) et id du root = id du rootrequest
		if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 129) {
			fmt.Printf("recu rootreply correct\n")
			if debugH {
				fmt.Println("le mess dans bufR ", bufR)
			}
			brk1 += 1
			tps = 2
		}
		if bufR[4] == 254 {
			if debugH {
				fmt.Printf("message erreur\n")
				fmt.Println(string(bufR[7:]))
			}
		}
	}
}

// j'ai recu une rootrequest et je te reponds pas le hash de ma racine (racine hacher beurk beurk)
func rootmess(adr net.Addr, conn net.PacketConn) {
	if debugRQ {
		fmt.Printf("rootRequest for you ")
	}
	//remplir un message avec type 129 et hash de la racine dans le corps length =32
	bufE := rempMess(129, 32) //a peut etre pas obligatoire
	if debugRQ {
		fmt.Println("root mess: le mess dasn bufE ", bufE)
	}
	//envoie de bufE
	address := adr.String()
	adr2, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		fmt.Printf("resolve\n")
		log.Fatal(err)
	}
	_, err = conn.WriteTo(bufE, adr2)
	if err != nil {
		fmt.Println("write")
		log.Fatal(err)
	}
	if debugRQ {
		fmt.Println("hash racine envoyer")
	}

}

func getDatumMess(adr net.Addr, conn net.PacketConn) {
	if debugD {
		fmt.Printf("get datum mess ")
	}
	// //remplir un message avec type 129 et hash de la racine dans le corps length =32
	// bufE := rempMess(2, 32) //a peut etre pas obligatoire
	// if debugRQ {
	// 	fmt.Println("root mess: le mess dasn bufE ", bufE)
	// }
	// //envoie de bufE
	// address := adr.String()
	// adr2, err := net.ResolveUDPAddr("udp", address)
	// if err != nil {
	// 	fmt.Printf("resolve\n")
	// 	log.Fatal(err)
	// }
	// _, err = conn.WriteTo(bufE, adr2)
	// if err != nil {
	// 	fmt.Println("write")
	// 	log.Fatal(err)
	// }
	// if debugRQ {
	// 	fmt.Println("hash racine envoyer")
	// }

}

func waitwaitmessages(conn net.PacketConn, name string) {
	//attendre un message
	for {
		bufR := make([]byte, 256)
		_, addr, err := conn.ReadFrom(bufR)
		if err != nil {
			//fmt.Printf("read\n")
			//log.Fatal(err)
		} else {
			fmt.Printf("else waitwait\n")
			switch bufR[4] {
			case 0: // hello
				fmt.Printf("recu hello du waitwait\n")
				helloreply(addr, bufR, name, conn)

			case 128:
			//bon dieu pourquoi je recoit un helloreply ????
			// helloreply

			case 1: // rootrequest
				rootmess(addr, conn)

			// case 129: //rootreply

			case 2: // getdatum
			//verif datum
			//nodatummess
			//datummess

			// case 131: // nodatum

			// case 130: // datum

			case 254: //erreur
				fmt.Printf("erreur\n")
				fmt.Println(string(bufR[7:]))
				// break
			default:
				break
			}
		}
	}

}

// avoir la liste de tous les pairs connectes au serveur
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

// avoir les informations dun certain pair
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

func envoie(name string, test string) {
	conn := session(name)
	//waitwaitmessages(conn, name)

	liste := chercherPairs()
	fmt.Printf("liste : %s\n", liste)
	var adr string
	if liste != "" {
		pair := chercherPair(test)
		fmt.Printf("name : %s \n", pair.Name)
		i := 0
		for i = 0; i < len(pair.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		adr = fmt.Sprintf("%s:%d", pair.Addresse[i-1].Host, pair.Addresse[i-1].Port)
	}
	fmt.Println("*********************************************************************************************")
	handshake(name, adr, conn, 0)
	// rootrequestmess(adr, conn)

	defer conn.Close()
}

func main() {
	name := "harmouny"
	testN := "sarah"
	fmt.Printf("nom : %s\n", name)
	// // session(name)
	// fmt.Println()
	// liste := chercherPairs()
	// fmt.Printf("liste : %s\n", liste)
	// if liste != "" {
	// 	pair := chercherPair(name)
	// 	fmt.Printf("name : %s \n", pair.Name)
	// 	for i := 0; i < len(pair.Addresse); i++ {
	// 		fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)

	// 	}
	// }
	// hello(name, "Ju")

	// initialisationArbre()
	// affichageArbre()
	// test := make([]byte, 256)
	// // buf := rempMessArbre("coucou", test)
	// // fmt.Println(buf)

	// ajoutMess("beurk", test)
	// affichageArbre()
	// ajoutMess("bip", test)
	// affichageArbre()
	// ajoutMess(name, test)
	// affichageArbre()

	envoie(name, testN)

	// conn := session(testN)
	// fmt.Printf("\n\n\n\nboucle attente message \n\n")
	// waitwaitmessages(conn, testN)

}
