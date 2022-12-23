package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
	// "math/rand"
)

// variable de debugage
var debug = false   // fonction session
var debugP = false  // fonction recherche de pair
var debugH = false  // fonction hello et helloReply
var debugA = false  // fonction arbre de Merkle
var debugRQ = false // fonction root request
var debugM = false  // fonction rempMess
var debugD = false  // fonction datum etc
var debugN = true   // fonction nat etc

// variable globale
var myIP = 4
var idMess = 0
var a arbreMerkle
var vide []byte
var serverADDRESS string
var name = "kitty"

// recevoir ip et port du serveur
type jsonMessage struct {
	Host string `json:"ip"`
	Port int64  `json:"port"`
}

// senregistrer au serveur
type jsonEnregistrement struct {
	Name string `json:"name"`
	// Key  []byte `json:"key"`
}

// information dun pair enregistrer dans le serveur
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

// ajout dun message dans un arbre
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

// affichage des message de larbre
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

// trouver si le hash donne appartient a notre arbre
func goodhash(hash []byte) bool {
	h := sha256.Sum256(a.racine.value)
	if bytes.Equal(h[:], hash) {
		return true
	} else {
		return goodhashnoued(a.racine, hash)
	}

}
func goodhashnoued(n *noeud, hash []byte) bool {
	if n == nil {
		fmt.Printf("Vide\n")
		return false
	} else {
		if n.droit.value[0] == 0 {
			if bytes.Compare(n.value, hash) == 0 {
				return true
			}
		} else {
			goodhashnoued(n.gauche, hash)
			goodhashnoued(n.droit, hash)
		}
	}
	return false
}

// https://tech-wiki.online/fr/golang-data-structure-binary-search-tree.html

// remplissage de la valeur dun noeud
func rempNoeudArbre(gauche *noeud, droit *noeud) []byte {
	lenNoeud := 1 + 32 + 32
	buf := make([]byte, lenNoeud)

	hg := sha256.Sum256(gauche.value)
	hd := sha256.Sum256(droit.value)
	buf[0] = 1
	k := 32
	for i := 0; i < 32; i++ {
		buf[i+1] = hg[i]
		buf[i+1+k] = hd[i]
	}

	return buf
}

// remplissage de la valeur dune feuille
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

// remplir un message pour la reponse Datum
func rempDatum(hash []byte) ([]byte, int) {
	buf := make([]byte, 1024)
	n := 0
	var nD *noeud
	h := sha256.Sum256(a.racine.value)
	if bytes.Equal(h[:], hash) {
		nD = a.racine
	} else {
		no := a.racine
		hg := no.value[1:33]
		hd := no.value[33:]
		for (!bytes.Equal(hash, hd)) && (!bytes.Equal(hash, hg)) {
			no = no.gauche
			hg = no.value[1:33]
			hd = no.value[33:]
		}
		if bytes.Equal(hash, hd) {
			nD = no.droit
		} else if bytes.Equal(hash, hg) {
			nD = no.gauche
		}
	}
	taille := 1 + 4 + 32 + 2
	for nD.value[0] != 0 {
		length := int(binary.BigEndian.Uint16(nD.droit.value[taille-2 : taille]))
		copy(buf[n:(n+taille+length)], nD.droit.value)
		n += taille + length
		nD = nD.gauche
	}

	length := int(binary.BigEndian.Uint16(nD.value[taille-2 : taille]))

	copy(buf[n:(n+taille+length)], nD.value)
	n += taille + length
	if debugD {
		fmt.Println("buf ", buf[:n])
	}
	n += 32
	bufF := make([]byte, n)
	copy(bufF[:32], hash)
	copy(bufF[32:], buf)
	return bufF, n
}

// affichage dune reponse Datum
func afficheDatum(bufR []byte) {
	lenghtbyte := bufR[5:7]
	buf := bytes.NewReader(lenghtbyte)
	var n uint16
	binary.Read(buf, binary.BigEndian, &n)
	if debugD {
		fmt.Println("taille ", int(n))
		fmt.Println("message datum", bufR)
	}
	deb := 4 + 1 + 2 + 32
	for int(n) > deb {
		if debugD {
			fmt.Println("\n\ntaille ", deb)
			fmt.Println("message datum", bufR[deb:])
		}
		deb += 1
		date := bufR[deb:(deb + 4)]
		buf := bytes.NewReader(lenghtbyte)
		var n uint16
		binary.Read(buf, binary.BigEndian, &n)
		deb += 4
		hash := bufR[deb:(deb + 32)]
		deb += 32
		length := int(binary.BigEndian.Uint16(bufR[deb:(deb + 2)]))
		deb += 2
		mess := string(bufR[deb:(deb + length)])
		deb += length
		if hash[0] == 0 {
			fmt.Printf("message datant du %v, %v\n\n", date, mess)
		} else {
			fmt.Printf("message datant du %v, repondant a %v, %v\n\n", date, hash, mess)
		}
		if debugD {
			fmt.Println("ou ", n, deb)
		}

	}

}

// body peut etre username si hello/helloreply
func rempMess(typMess int, length int, body []byte, id []byte) []byte {
	var userlength int
	if typMess == 128 || typMess == 0 {
		userlength = len(body)
		length = 5 + userlength
	}

	// // id+type+length+taillebody
	// // ATTENTION MANQUE SIGNATURE
	buflen := 4 + 1 + 2 + length
	buf := make([]byte, buflen)

	var i int
	// generation id
	if typMess <= 127 && typMess >= 0 || typMess == 132 {
		idMess += 1
		idMessbyte := make([]byte, 4)
		binary.BigEndian.PutUint32(idMessbyte, uint32(idMess))
		for i = 0; i < 4; i++ {
			buf[i] = idMessbyte[i]
		}
	} else if typMess <= 255 && typMess >= 128 {
		fmt.Println("remp mess reponse ")
		for i = 0; i < 4; i++ {
			buf[i] = id[i]
		}
	}
	// type
	buf[i] = byte(typMess)
	i++

	//length
	lenghtbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenghtbyte, uint16(length))
	for k := 0; k < 2; k++ {
		buf[k+i] = lenghtbyte[k]
	}
	i += 2

	// body
	if typMess == 129 { // cas root
		fmt.Println("remp mess root")
		hracine := sha256.Sum256(a.racine.value)
		for k := 0; k < length; k++ {
			buf[k+i] = hracine[k]
		}
		i += length
	} else if typMess == 128 || typMess == 0 { //cas helloreply
		fmt.Println("remp mess hello")
		// Flags et flags contd
		for k := 0; k < 4; k++ {
			buf[k+i] = 0
		}
		i += 4
		// username length
		buf[i] = byte(userlength)
		i++
		// username
		for k := 0; k < userlength; k++ {
			buf[k+i] = body[k]
		}
		i += userlength
	} else if typMess == 1 { // cas rootrequest
		fmt.Println("remp mess rootrequest")
	} else if typMess == 132 || typMess == 133 { // cas nat client
		fmt.Println("remp mess nat")
		fmt.Println(body)
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	} else if typMess == 2 { // getDatum
		fmt.Println("remp mess getDatum")
		if debugM {
			fmt.Println(body)
		}
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	} else if typMess == 130 { // datum
		fmt.Println("remp mess Datum")
		fmt.Println("remp mess getDatum")
		if debugM {
			fmt.Println(body)
		}
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	} else if typMess == 131 { // Nodatum
		fmt.Println("remp mess NoDatum")
		if debugM {
			fmt.Println(body)
		}
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	}
	// continuer avec la key
	// continuer avec datum
	if debugM {
		fmt.Println("le mess dans rempMEss ", buf)
	}
	return buf
}

// envoie dun nat transversal client
func nat(conn net.PacketConn, adr *net.UDPAddr) {
	if debugN {
		fmt.Println("ADRESS SERVER ", serverADDRESS)
	}
	fmt.Println("fonction nat")
	//je suis A je veux me connecter a B
	//envoie un message non soliciter au serveur nat traversal client 132
	//implementer dans waitwait le cas si je recoit le nat transerval server 133
	// alors je doit reagir en envoyant helloreply a A
	//un peu plus tard A (moi) envoie une requete hello a B

	//remplir message
	if debugN {
		fmt.Println("adr ", adr)
		fmt.Println("adrIP taille ", len(adr.IP))
		for i := 0; i < len(adr.IP); i++ {
			fmt.Printf("adrIP %d %v\n", i, adr.IP[i])
		}

		fmt.Println("adrPort ", adr.Port)
	}
	fmt.Println("tchooo")
	buf := make([]byte, 18)
	fmt.Println("tchooo")
	for i := 0; i < 16; i++ {
		fmt.Println("tchooo ", i)
		fmt.Println(adr.IP[i+len(adr.IP)-16])
		buf[i] = adr.IP[i+len(adr.IP)-16]
	}

	adrport := uint16(adr.Port) ^ 0xFFFF
	fmt.Println("adrport ", adrport)
	fmt.Println("oxffff ", 0xFFFF)

	bufport := make([]byte, 2)
	binary.BigEndian.PutUint16(bufport, uint16(adr.Port))
	fmt.Println("bufport", bufport)

	buf[16] = bufport[0]
	buf[17] = bufport[1]

	if debugN {
		fmt.Println("mess buf nat ", buf)
		fmt.Println("mess buf nat taille ", len(buf))
		fmt.Println("port ", buf[4], buf[5])
	}

	bufE := rempMess(132, 18, buf, vide)
	// bufE[4] = 40
	if debugN {
		fmt.Println("mess bufE nat ", bufE)
	}

	server, err := net.ResolveUDPAddr("udp", serverADDRESS)
	if err != nil {
		fmt.Println("Resolveudp NAT")
		log.Fatal(err)
	}
	_, err = conn.WriteTo(bufE, server)
	if debug {
		fmt.Println("serveur ip", server.IP)
		fmt.Println("serveur port", server.Port)
	}
	if err != nil {
		fmt.Printf("write\n")
		log.Fatal(err)
	}
	bufR := make([]byte, 1024)
	_, _, err = conn.ReadFrom(bufR)
	if err == nil {
		fmt.Println("Erreur read")
		fmt.Println(string(bufR[7:]))
	}

	// waitwaitmessages(conn)
	// else {
	// 	fmt.Printf("read nat\n")
	// 	log.Fatal(err)
	// }

	if debug {
		fmt.Println("nat envoyer")
	}
}

// recu dun nat transversal server
func natReceive(conn net.PacketConn, bufR []byte, name string) {
	if debug {
		fmt.Printf("j'ai recu nat du serveur")
	}
	adr := bufR[7:13] // car ipv4
	adrtostring := string(adr)
	adr2, err := net.ResolveUDPAddr("udp", adrtostring)
	if err != nil {
		fmt.Printf("resolve")
		log.Fatal(err)
	}
	namebyte := []byte(name)
	bufE := rempMess(128, 0, namebyte, bufR)

	_, err = conn.WriteTo(bufE, adr2)
}

// envoie dun helloreply (apres avoir recu un hello)
func helloreply(adr net.Addr, bufR []byte, conn net.PacketConn) {
	if debugH {
		fmt.Printf("hello\n")
		fmt.Println("le mess dans bufR ", bufR)
	}
	// remplir pour un message avec NOTRE id type 128 et le bufrecu du hello
	userbyte := []byte(name)
	bufE := rempMess(128, 0, userbyte, bufR)
	if debug {
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

// envoie dun hello et attend helloreply
func hello(pair jsonPeer, conn net.PacketConn) {
	if debugH {
		fmt.Printf("hello\n")
	}
	for i := 0; i < len(pair.Addresse); i++ {
		if debugH {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)
		fmt.Printf("addrconn %s \n", addrconn)
		addr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve udp\n")
			log.Fatal(err)
		}

		brk1 := 0
		tps := 2
		for brk1 != 1 {
			bufE := make([]byte, 256)

			if brk1 != 1 {
				// preparation message bufE ENVOYE HELLO
				userbyte := []byte(name)
				bufE = rempMess(0, 0, userbyte, vide)
				if debugH {
					fmt.Println("le mess dans bufE ", bufE)
					fmt.Println("mess lisible ", string(bufE[7:]))
				}
				_, err = conn.WriteTo(bufE, addr2)
				if err != nil {
					fmt.Printf("write\n")
					log.Fatal(err)
				}
				fmt.Printf("hello envoye !\n")
			}

			if debugH {
				fmt.Printf("\n\n\n")
			}
			// prepare bufrecevoir pour ecrire le message recu dedans
			bufR := make([]byte, 256)
			conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
			_, _, err = conn.ReadFrom(bufR)
			if debugH {
				fmt.Println(bufR[:20])
			}
			if err != nil && tps > 20 {
				fmt.Println("nat handshake")
				nat(conn, addr2)
				for {
					bufR := make([]byte, 256)
					_, _, err = conn.ReadFrom(bufR)
					if err == nil {
						fmt.Println(bufR)
						break
					}
				}
				// waitwaitmessages(conn, name)
				break
			} else if err != nil {
				fmt.Printf("\n\nAttente\n")
				tps = tps * 2
				if tps > 64 {
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
				tps = 2
			} else if bufR[4] == 254 {
				if debugH {
					fmt.Printf("message erreur\n")
					fmt.Println(string(bufR[7:]))
				}
			} else {
				fmt.Printf("Erreur\n")
				fmt.Println((bufR[:20]))

			}
			if brk1 > 2 {
				fmt.Printf("PROBLEME HELLO\n")
				break
			}
		}
	}
	//defer conn.Close()
}

// envoie dun hello et attend un helloreply
// attend un hello et envoie un helloreply
// -> handshake avec le serveur
func handshake(addrconn string, conn net.PacketConn) {
	if debugH {
		fmt.Printf("handshake\n")
	}
	if debugN {
		fmt.Printf("addrconn %s \n", addrconn)
		// fmt.Printf("addrconn2 %s \n", addr2)
	}
	addr2, err := net.ResolveUDPAddr("udp", addrconn)
	if err != nil {
		fmt.Printf("resolve udp\n")
		log.Fatal(err)
	}

	brk1 := 0
	brk2 := 0
	tps := 2
	for brk1 != 1 || brk2 != 1 {
		// preparation message bufE ENVOYE HELLO
		buf := make([]byte, 1)
		userbyte := []byte(name)
		bufE := rempMess(0, 0, userbyte, buf)
		if brk1 != 1 {
			if debugH {
				fmt.Println("le mess dans bufE ", bufE)
				fmt.Println("mess lisible ", string(bufE[7:]))
			}
			_, err = conn.WriteTo(bufE, addr2)
			if err != nil {
				fmt.Printf("write\n")
				log.Fatal(err)
			}
			fmt.Printf("hello envoye !\n")
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
			tps = 2
		}
		if bufR[4] == 254 {
			if debugH {
				fmt.Printf("message erreur\n")
				fmt.Println(string(bufR[7:]))
			}
		} else if bufR[4] == 0 { // hello recu
			fmt.Println("hello serveur")
			helloreply(addr2, bufR, conn)
			brk2 += 1
		}
		if brk1 > 2 || brk2 > 2 {
			fmt.Printf("PROBLEME HANDSHAKE\n")
			break
		}
	}
	//defer conn.Close()
}

// connection et enregistrement au serveur
func session() net.PacketConn {
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
	if debug {
		fmt.Println(m)
		fmt.Println(jsonValue)
	}

	repPost, err := http.Post("https://jch.irif.fr:8443/register", "application/json", bytes.NewBuffer(jsonValue))
	if err != nil {
		log.Fatal(err)
	}
	if debug {
		fmt.Println(repPost.StatusCode)
	}
	if repPost.StatusCode != 204 {
		fmt.Printf("status\n")
		log.Fatal("status")
	}
	// ecoute sur port en udp
	// 49 152 à 65 535
	// s := rand.NewSource(time.Now().UnixNano())
	// r := rand.New(s)
	// limitPort := 65535 - 1024
	// i := r.Intn(limitPort) + 1024
	// port := fmt.Sprintf(":%d", i)
	port := fmt.Sprintf(":%d", 7283)
	if debug {
		fmt.Printf("port : %s\n", port)
	}
	conn, err := net.ListenPacket("udp", port)
	if debug {
		fmt.Printf("j'ecoute %v\n", conn.LocalAddr().String())
	}
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	//defer conn.Close()
	// handshake avec le serveur
	for i := 0; i < len(message); i++ {
		fmt.Printf("\n\n")
		if debug {
			fmt.Printf("\n\ndebut boucle\n")
		}
		addrconn := fmt.Sprintf("[%s]:%d", message[i].Host, message[i].Port)
		serverADDRESS = addrconn
		// envoie hello et dedans appel helloreply si recoit hello du retour sort quand a recu le helloreply
		// du serveur plus envoyer hello reply au serveur
		handshake(addrconn, conn)
	}
	return conn
}

// demande de rootrequest
func rootrequestmess(pair jsonPeer, conn net.PacketConn) []byte {
	if debugRQ {
		fmt.Println("rootrequest please")
	}
	bufR := make([]byte, 256)
	for i := 0; i < len(pair.Addresse); i++ {
		if debugH {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)
		fmt.Printf("addrconn %s \n", addrconn)

		// envoie de bufE
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve")
			log.Fatal(err)
		}
		tps := 2
		brk1 := 0
		for brk1 != 1 {
			bufE := rempMess(1, 0, vide, vide)
			if debugRQ {
				fmt.Println("root request mess : dans bufE ", bufE)
			}
			_, err = conn.WriteTo(bufE, adr2)
			if err != nil {
				fmt.Println("write")
				log.Fatal(err)
			}
			fmt.Printf("Rootrequest envoye !\n")

			// prepare bufrecevoir pour ecrire le message recu dedans

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
	return bufR[7:39]

}

// recu une rootrequest et reponse du hash de ma racine
func rootmess(adr net.Addr, conn net.PacketConn, bufR []byte) {
	fmt.Printf("rootRequest for you ")
	//remplir un message avec type 129 et hash de la racine dans le corps length =32
	bufE := rempMess(129, 32, vide, bufR)
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
	fmt.Println("hash racine envoyer")
}

// demande de message/datum via hash
func getDatumMess(pair jsonPeer, conn net.PacketConn, hash []byte) {
	if debugD {
		fmt.Println("getdatum please")
	}
	for i := 0; i < len(pair.Addresse); i++ {
		if debugH {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)
		fmt.Printf("addrconn %s \n", addrconn)

		//envoie de bufE
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve")
			log.Fatal(err)
		}
		tps := 2
		brk1 := 0
		for brk1 != 1 {
			bufE := rempMess(2, 32, hash, vide)
			if debugD {
				fmt.Println("getdatum mess : dans bufE ", bufE)
			}
			_, err = conn.WriteTo(bufE, adr2)
			if err != nil {
				fmt.Println("write")
				log.Fatal(err)
			}
			fmt.Println("demande getdatum envoyer! ")

			// prepare bufrecevoir pour ecrire le message recu dedans
			bufR := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
			_, _, err = conn.ReadFrom(bufR)
			if err != nil {
				fmt.Printf("Attente\n")
				tps = tps * 2
				if tps >= 32 {
					tps = 2
				}
			}
			// verif que cest bien un datumreply (donc type 130 ou 131 nodatum) et id du datum = id du getdatum
			if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 131) {
				// verif la valeur du hash
				if bytes.Compare(hash, bufR[7:39]) == 0 {
					if debugD {
						fmt.Println("meme hash no")
					}
					fmt.Printf("recu NOdatum correct\n")
					// appel fonction pour afficher les mess du hash
				}
				brk1 += 1
				tps = 2
			}
			if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 130) {
				// verif la valeur du hash
				if bytes.Compare(hash, bufR[7:39]) == 0 {
					if debugD {
						fmt.Println("meme hash datum")
					}
					fmt.Printf("recu datum correct\n")
					afficheDatum(bufR)
				}
				if debugD {
					fmt.Println("le mess dans bufR ", bufR)
				}
				brk1 += 1
				tps = 2
			}
			if bufR[4] == 254 {
				if debugD {
					fmt.Printf("message erreur\n")
					fmt.Println(string(bufR[7:]))
				}
			}
		}
	}
}

// pas de message correspondant au hash demande
func noDatumMess(adr net.Addr, conn net.PacketConn, bufR []byte) {
	if debugRQ {
		fmt.Println("nodatumMess please")
	}
	// remplir un message avec type  131 avec le hash demander
	bufE := rempMess(131, 32, bufR[7:39], bufR)
	if debugRQ {
		fmt.Println("nodatum mess: le mess dasn bufE ", bufE)
	}
	// envoie de bufE
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
		fmt.Println("nodatum envoyer")
	}
}

// envoie de toutes les reponses precedent le hash demande
func datumMess(adr net.Addr, conn net.PacketConn, bufR []byte) {
	if debugRQ {
		fmt.Println("datumMess please")
	}
	// remplir un message avec type  130 avec le hash demander
	hash := bufR[7:39]
	body, n := rempDatum(hash)
	bufE := rempMess(130, n, body, bufR)
	if debugRQ {
		fmt.Println("datum mess: le mess dasn bufE ", bufE)
	}
	// envoie de bufE
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
		fmt.Println("datum envoyer")
	}
}

// attente infini de message
func waitwaitmessages(conn net.PacketConn) {
	//attendre un message
	for {
		//fmt.Println("LA")
		bufR := make([]byte, 256)
		_, addr, err := conn.ReadFrom(bufR)
		if err != nil {
			//fmt.Printf("read\n")
			//log.Fatal(err)
		} else {
			fmt.Println("LA")
			switch bufR[4] {
			case 0: // hello
				helloreply(addr, bufR, conn)

			case 128:
				// helloreply
				fmt.Println("hello reply non demander")
				// hello(addr.String(), conn)

			case 1: // rootrequest
				rootmess(addr, conn, bufR)
			case 133: // nat s
				fmt.Println("IM HERE ")
				adr := bufR[7:13] // car ipv4
				adrtostring := string(adr)
				adr2, err := net.ResolveUDPAddr("udp", adrtostring)
				if err != nil {
					fmt.Println("resolve wait")
					log.Fatal(err)
				}
				helloreply(adr2, bufR, conn)

			// case 129: // rootreply

			case 2: // getdatum
				if debug {
					fmt.Println("getdatum recuuu")
				}
				//verif qu'on a le hash
				hashrecu := bufR[7:39]
				if goodhash(hashrecu) == true {
					//datummess
					// datumMess(addr, conn, bufR)
				} else {
					noDatumMess(addr, conn, bufR)
				}
			// case 131: // nodatum

			// case 130: // datum

			case 254: //erreur
				fmt.Printf("erreur\n")
				fmt.Println(string(bufR[7:]))
				// break
			default:
				fmt.Printf("mess de type inconnu")
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

func main() {
	// length := 257
	// lenghtbyte := make([]byte, 2)
	// binary.BigEndian.PutUint16(lenghtbyte, uint16(length))
	// nowBuffer := bytes.NewReader(lenghtbyte)
	// var len uint16
	// binary.Read(nowBuffer,binary.BigEndian,&len)

	// // buf := bytes.NewBuffer(lenghtbyte)
	// // len, _ := binary.ReadVarint(buf)
	// fmt.Println(length, lenghtbyte, len)

	initialisationArbre()
	affichageArbre()

	// ajoutMess("beurk", vide)
	// time.Sleep(2)
	// // affichageArbre()
	// ajoutMess("bip", vide)
	// time.Sleep(2)
	// // affichageArbre()
	// ajoutMess("boop", vide)
	// time.Sleep(2)
	// affichageArbre()
	// time.Sleep(2)

	// h := sha256.Sum256(a.racine.value)
	// ajoutMess("connection reussie", h[:])

	// h = sha256.Sum256(a.racine.value)
	// buf, n := rempDatum(h[:])
	// fmt.Println(string(buf))
	// fmt.Println(n)
	// id := []byte{1, 1, 1, 1}
	// bufE := rempMess(130, n, buf, id)
	// fmt.Println()
	// afficheDatum(bufE)

	conn := session()
	fmt.Println("*********************************************************************************************")
	// // waitwaitmessages(conn)

	liste := chercherPairs()
	fmt.Printf("liste : %s\n", liste)
	var pair jsonPeer
	if liste != "" {
		pair = chercherPair("jch")
		fmt.Printf("name : %s \n", pair.Name)
		i := 0
		for i = 0; i < len(pair.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		// adr = fmt.Sprintf("[%s]:%d", pair.Addresse[i-1].Host, pair.Addresse[i-1].Port)
	}
	fmt.Println("*********************************************************************************************")
	// fmt.Println("addddddrrrrr ", adr)

	hello(pair, conn)
	fmt.Println("*********************************************************************************************")
	hash := rootrequestmess(pair, conn)
	fmt.Println()
	fmt.Println("hash ", hash)
	fmt.Println("*********************************************************************************************")
	getDatumMess(pair, conn, hash)
	fmt.Println()
	ajoutMess("connection reussie", hash)
	affichageArbre()

	// defer conn.Close()

}
