package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
	// "math/rand"
)

// variable debugage
var debug = false   // fonction session
var debugP = false  // fonction recherche de pair
var debugH = false  // fonction hello et helloReply
var debugA = false  // fonction arbre de Merkle
var debugRQ = false // fonction root request
var debugM = false  // fonction rempMess
var debugD = false  // fonction datum etc
var debugN = false  // fonction nat etc
var debugIP = false

// variable globale
var wg sync.WaitGroup
var justhelloplease = false // si false alors on fera tout les cas dans waitwait
var myIP = 4
var idMess = 100
var a arbreMerkle // notre arbre de message
var vide = make([]byte, 256)
var serveur jsonPeer
var name = "Blue"
var conn net.PacketConn
var pair jsonPeer
var messArbre [][]byte // savoir si les messages ont ete mis a jour, on garde en memoire les anciens

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

// affichage simpliste de larbre
func affichageArbre() {
	affichageNoeud(a.racine)
	fmt.Printf("\n\n")
}

// affichage juste des messages, pas de date ni hash
func affichageNoeud(n *noeud) {
	if n == nil {
		fmt.Printf("Vide\n")
	} else {
		if n.value[0] == 0 {
			fmt.Println(string(n.value[(1 + 4 + 32 + 2):]))
		} else {
			affichageNoeud(n.gauche)
			affichageNoeud(n.droit)
		}
	}
}

// remplissage dun noeud de larbre (value)
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

// remplissage dune feuille dun arbre (value)
// mess : le message
// rep le hash du message auquel on repond, vide si pas de reponse
func rempMessArbre(mess string, rep []byte) []byte {
	messbyte := []byte(mess)
	messlength := len(messbyte)
	lenMess := 1 + 4 + 32 + 2 + messlength
	buf := make([]byte, lenMess)

	buf[0] = 0
	// transformation de la date en seconde
	now := time.Now()
	janvier := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
	date := now.Sub(janvier)
	sec := date.Seconds()
	if debugA {
		fmt.Printf("date %v\nsec%v\n", date, sec)
	}
	secbyte := make([]byte, 4)
	binary.BigEndian.PutUint32(secbyte, uint32(sec))
	// remplissage de buf
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

// hash appartient a larbre
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
		if debugD {
			fmt.Println("\nvalue ", n.value, hash)
		}
		if n.value[0] == 0 {
			return false
		} else if n.value[0] == 1 {
			hg := n.value[1 : 32+1]
			hd := n.value[1+32:]
			if debugD {
				fmt.Println("hg ", hg)
				fmt.Println("hd ", hd)
			}
			if bytes.Equal(hg[:], hash) || bytes.Equal(hd[:], hash) {
				return true
			} else {
				bd := goodhashnoued(n.droit, hash) // pas vraiment necessaire car droit est une feuille donc pas denfant
				bg := goodhashnoued(n.gauche, hash)
				return bd || bg
			}
		}
	}
	return false
}

// remplissage dun message a envoyer
// body peut etre username si hello/helloreply
func rempMess(typMess int, length int, body []byte, id []byte) []byte {
	var userlength int
	if typMess == 128 || typMess == 0 {
		userlength = len(body)
		length = 5 + userlength
	}

	// id+type+length+taillebody
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
	} else if typMess == 128 || typMess == 0 { // cas helloreply et hello
		if debugM {
			fmt.Println("remp mess hello/helloreply")
		}
		// Flags
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
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	} else if typMess == 2 || typMess == 130 || typMess == 131 { // getDatum et datum et noDatum
		fmt.Println("remp mess getDatum/ Datum/ noDatum")
		if debugM {
			fmt.Println(body)
		}
		for k := 0; k < length; k++ {
			buf[k+i] = body[k]
		}
		i += length
	}

	if debugM {
		fmt.Println("le mess dans rempMEss ", buf)
	}
	return buf
}

// fonction qui envoie un hello et attend un helloreply
// utilise que lors de la connection au serveur
func handshake(addrconn string) {
	if debugH {
		fmt.Printf("handshake\n")
	}
	if debugN {
		fmt.Printf("addrconn %s \n", addrconn)
	}
	addr2, err := net.ResolveUDPAddr("udp", addrconn)
	if err != nil {
		fmt.Printf("resolve udp\n")
		log.Fatal(err)
	}

	brk1 := 0 // == 1 si on a recu helloreply du serveur
	brk2 := 0 // == 1 si on a recu un hello du serveur
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
		} else if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
			// verif que cest bien un helloreply (donc type 128) et id du hello = id du helloreply
			if debugH {
				fmt.Printf("recu helloreply correct\n")
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
		} else if bufR[4] == 0 { // hello recu du serveur
			fmt.Println("hello serveur")
			helloreply(addr2, bufR)
			brk2 += 1
		}
		if brk1 > 2 || brk2 > 2 {
			fmt.Printf("PROBLEME HANDSHAKE\n")
			break
		}
	}
}

// enregistrement au serveur
func session() {
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
	// ecoute sur port en udp 1024 à 65 535
	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)
	limitPort := 65535 - 1024
	i := r.Intn(limitPort) + 1024
	port := fmt.Sprintf(":%d", i)

	// a utilise (ligne suivante commente) si on veut relancer le programme avec le meme nom et eviter des adresses inutiles
	// port := fmt.Sprintf(":%d", 8921)
	if debug {
		fmt.Printf("port : %s\n", port)
	}
	conn, err = net.ListenPacket("udp", port)
	if debug {
		fmt.Printf("j'ecoute %v\n", conn.LocalAddr().String())
	}
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	serveur.Name = "serveur"
	// handshake avec le serveur sur toutes ses adresses
	for i := 0; i < len(message); i++ {
		fmt.Printf("\n\n")
		if debug {
			fmt.Printf("\n\ndebut boucle\n")
		}
		addrconn := fmt.Sprintf("[%s]:%d", message[i].Host, message[i].Port)
		adrs := jsonMessage{Host: message[i].Host, Port: message[i].Port}
		serveur.Addresse = append(serveur.Addresse, adrs)

		// envoie hello et dedans appel helloreply si recoit hello du retour sort
		// quand a recu le helloreply du serveur plus envoyer hello reply au serveur
		handshake(addrconn)
		if myIP == 4 { // ne pas chercher a utilise ipv6 si on ne la pas (wifi de la fac)
			i++
		}

	}
}

// attente infini de message
func waitwaitmessages() {
	defer wg.Done()
	lettre := 'a'
	// attendre un message
	for {
		if justhelloplease == true {
			for i := 0; i < len(serveur.Addresse); i++ {
				addrconn := fmt.Sprintf("[%s]:%d", serveur.Addresse[i].Host, serveur.Addresse[i].Port)
				addr2, err := net.ResolveUDPAddr("udp", addrconn)
				if err != nil {
					fmt.Printf("resolve udp\n")
					log.Fatal(err)
				}
				// helloreply non solicite
				helloreply(addr2, vide)
			}
		} else {
			hello(serveur)
			// publication dun message toutes les 2 sec
			// (pour tester la mise a jour de larbre)
			ajoutMess(string(lettre), vide)
			lettre += 1
		}
		if justhelloplease == false {
			bufR := make([]byte, 256)
			_, addr, err := conn.ReadFrom(bufR)
			if err != nil { // rien recu
				//fmt.Printf("read\n")
				//log.Fatal(err)
			} else {
				switch bufR[4] {
				case 0: // hello
					fmt.Println("hello recu")
					helloreply(addr, bufR)
					break
				case 128: // helloreply
					fmt.Println("hello reply non demander")
					// handshake(addr.String())
					break
				case 1: // rootrequest
					fmt.Println("rootrequest recu")
					rootmess(addr, bufR)
					break
				case 129: // rootreply
					fmt.Println("root reply non demander")
					break
				case 133: // nat s
					fmt.Println("nat serveur recu")
					natReceive(bufR)
					break
				case 2: // getdatum
					fmt.Println("getdatum recu")
					// verif qu'on a le hash
					hashrecu := bufR[7:39]
					if goodhash(hashrecu) == true {
						datumMess(addr, bufR)
					} else {
						noDatumMess(addr, bufR)
					}
					break
				case 130: // datum
					fmt.Println("datum non demander")
					break
				case 131: // no datum
					fmt.Println("no datum non demander")
					break
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
		time.Sleep(2 * time.Second)
	}
}

// fonction qui envoie hello et attend helloreply
func hello(pair jsonPeer) {
	if debugH {
		fmt.Printf("hello\n")
	}

	// envoie hello a toutes les adresses de pair enregistre dans le serveur
	nbAdd := len(pair.Addresse)
	indxdep := 0
	if nbAdd >= 3 {
		indxdep = nbAdd - 2
	}
	for i := indxdep; i < len(pair.Addresse); i++ {
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)
		if debugH {
			fmt.Printf("addrconn %s \n", addrconn)
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
		}
		addr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve udp\n")
			log.Fatal(err)
		}

		brk1 := 0 // == 1 si on a recu un helloreply
		tps := 2
		notHR := false //mis a true si on recoit un message different de hello reply
		//permet de ne pas renvoyer de hello inutile
		var bufE []byte
		for brk1 != 1 {
			if notHR == false {
				bufE = make([]byte, 256)
			}
			if brk1 != 1 { // tant que rien recu, on renvoie une demande de hello
				// preparation message bufE ENVOYE HELLO
				if notHR == false {
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
					if debugH {
						fmt.Printf("hello envoye !\n")
					}
				}
			}
			if debugH {
				fmt.Printf("\n\n\n")
			}

			// prepare bufrecevoir pour ecrire le message recu dedans
			bufR := make([]byte, 256)
			conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
			_, addr, err := conn.ReadFrom(bufR)
			if debugH {
				fmt.Println(bufR[:20])
			}
			if err != nil && tps > 15 {
				fmt.Println("nat handshake")
				nat(addr2)
				// for {
				// 	bufR := make([]byte, 256)
				// 	_, addr, err = conn.ReadFrom(bufR)
				// 	if err == nil {
				// 		fmt.Println(bufR)
				// 		break
				// 	}
				// }
				// hello(pair)
				fmt.Println("FIIIIINIIII *********")
				tps = 2
				brk1 += 1
			} else if err != nil {
				fmt.Printf("\n\nAttente\n")
				tps = tps * 2
				if tps > 32 {
					tps = 2
				}
			} else if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
				// verif que cest bien un helloreply (donc type 128) et id du hello = id du helloreply

				if debugH {
					fmt.Printf("recu helloreply correct\n")
					fmt.Println("le mess dans bufR ", bufR)
				}
				brk1 += 1
				tps = 2
			} else if bufR[4] == 254 {
				notHR = true
			} else if bufR[4] == 133 { // cest un nat transversal ! on doit y repondre
				fmt.Println("nat transversal dans hello ")
				natReceive(bufR)
				// MAIS APRES JE VEUX PAS CHANGER LE BUFR....
				notHR = true
			} else if bufR[4] == 0 && bufR[6] != 0 {
				fmt.Println("hello dans hello ")
				helloreply(addr, bufR)
				// MAIS APRES JE VEUX PAS CHANGER LE BUFR....
				notHR = true
			} else if bufR[4] == 1 {
				fmt.Println("root request dans hello")
				rootmess(addr, bufR)
				notHR = true
			} else if bufR[4] == 129 {
				fmt.Println("root dans hello")
				notHR = true
			} else if bufR[4] == 2 {
				fmt.Println("getdatum recu dans hello")
				// verif qu'on a le hash
				hashrecu := bufR[7:39]
				if goodhash(hashrecu) == true {
					//datummess
					datumMess(addr, bufR)
				} else {
					noDatumMess(addr, bufR)
				}
				notHR = true
			} else {
				// fmt.Println("addr", addr)
				// fmt.Println("(bufR[0:4] %d, bufE[0:4])%d", bufR[0:4], bufE[0:4])
				// fmt.Println((bufR[:20]))
				// MAIS APRES JE VEUX PAS CHANGER LE BUFR....
				notHR = true
			}
			if brk1 > 2 {
				fmt.Printf("PROBLEME HELLO\n")
				break
			}

		}
		// fmt.Println("fin boucle ", tps)
		if myIP == 4 {
			i++
		}
	}
}

// fonction qui envoie un helloreply apres avoir recu un hello
func helloreply(adr net.Addr, bufR []byte) {
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
	fmt.Println("helloReply envoye\n")
}

// demande de rootrequest
func rootrequestmess(pair jsonPeer) []byte {
	if debugRQ {
		fmt.Println("rootrequest please")
	}
	var rep []byte

	// envoie rootrequest a toutes les adresses de pair enregistre dans le serveur
	nbAdd := len(pair.Addresse)
	indxdep := 0
	if nbAdd >= 3 {
		indxdep = nbAdd - 2
	}
	for i := indxdep; i < len(pair.Addresse); i++ {
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)

		if debugRQ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
			fmt.Printf("addrconn %s \n", addrconn)
		}
		// envoie de bufE
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve")
			log.Fatal(err)
		}
		tps := 2
		brk1 := 0      // ==1 si on a recu rootReply
		notRQ := false //est mis a true si on a lu une reponse autre que rootreply
		var bufE []byte
		for brk1 != 1 {
			if notRQ == false {
				bufE = rempMess(1, 0, vide, vide)
				if debugRQ {
					fmt.Println("root request mess : dans bufE ", bufE)
				}
				_, err = conn.WriteTo(bufE, adr2)
				if err != nil {
					fmt.Println("write")
					log.Fatal(err)
				}
				fmt.Println("demande root request envoyer! ")
			}

			// prepare bufrecevoir pour ecrire le message recu dedans
			conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
			bufR := make([]byte, 256)
			_, _, err = conn.ReadFrom(bufR)
			if err != nil {
				fmt.Println("Attente")
				tps = tps * 2
				if tps >= 32 {
					tps = 2
				}
			} else if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 129) {
				// verif que cest bien un rootreply (donc type 129) et id du root = id du rootrequest
				fmt.Printf("recu rootreply correct\n")
				if debugRQ {
					fmt.Println("le mess dans bufR ", bufR)
				}
				brk1 = 1
				rep = bufR[7:39]
				tps = 2
			} else if bufR[4] == 254 {
				if debugRQ {
					fmt.Println("message erreur")
					fmt.Println(string(bufR[7:]))
					fmt.Println(bufR)
				}
				notRQ = true
			} else {
				fmt.Println("else !!!!!!!")
				fmt.Println("bufR, bfE", bufR[0:4], bufE[0:4])
				fmt.Println("le mess dans bufR ", bufR)
				notRQ = true
			}
			if brk1 == 1 {
				break
			}
		}
		if myIP == 4 {
			i++
		}
	}
	return rep
}

// fonction qui envoie un rootreply apres avoir recu une rootrequest
func rootmess(adr net.Addr, bufR []byte) {
	fmt.Printf("rootRequest for you \n")
	// remplir un message avec type 129 et hash de la racine dans le corps length =32
	bufE := rempMess(129, 32, vide, bufR)
	if debugRQ {
		fmt.Println("root mess: le mess dans bufE ", bufE)
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
	fmt.Println("hash racine envoyer")
}

// remplissage du body dun message aillant le hash et la value du noeud necessaire
func rempDatum(hash []byte) ([]byte, int) {
	n := 0
	// trouver le noeud auquel se rapporte le hash
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
	// remplir le bufF
	n = 32 + len(nD.value)
	bufF := make([]byte, n)
	copy(bufF[:32], hash)
	copy(bufF[32:], nD.value)
	if debugD {
		fmt.Println("bufFilnal ", bufF)
	}
	return bufF, n
}

// savoir si le hass est dans arbre (var messArbre), un tableau de hash
func notInArbre(hash []byte, arbre [][]byte) bool {
	if len(arbre) == 0 {
		return true
	}
	for i := 0; i < len(arbre); i++ {
		if bytes.Equal(hash, arbre[i]) {
			return false
		}
	}
	return true
}

// demande via getDatum, de tous les messages de pair
func afficheDatum(pair jsonPeer) {
	hash := rootrequestmess(pair)
	var hashArbre [][]byte
	if notInArbre(hash, messArbre) {
		messArbre = append(messArbre, hash)
		hashArbre = append(hashArbre, hash)
	}

	// parcours en largeur de larbre de pair
	for len(hashArbre) > 0 {
		hash = hashArbre[0]
		hashArbre = append(hashArbre[:0], hashArbre[1:]...)
		bufR := getDatumMess(pair, hash[:])
		// pas une reponse Nodatum
		if bufR != nil {
			lenghtbyte := bufR[5:7]
			buf := bytes.NewReader(lenghtbyte)
			var n uint16
			binary.Read(buf, binary.BigEndian, &n)
			if debugD {
				fmt.Println("hash ", hash)
				fmt.Println("len hashArbre ", len(hashArbre))
				fmt.Println("\ntaille ", lenghtbyte)
				fmt.Println("taille ", int(n))
				fmt.Println("taillemess ", len(bufR))
				fmt.Println("message datum", bufR)
			}

			deb := 4 + 1 + 2 + 32
			// bufR est une feuille
			if bufR[deb] == 0 {
				deb += 1
				janvier := time.Date(1970, time.January, 1, 0, 0, 0, 0, time.UTC)
				dateB := bufR[deb:(deb + 4)]
				buf = bytes.NewReader(dateB)
				var dateS uint32
				binary.Read(buf, binary.BigEndian, &dateS)
				date := janvier.Add(time.Duration(dateS) * time.Second)
				deb += 4
				hash := bufR[deb:(deb + 32)]
				deb += 32
				lengthB := bufR[deb:(deb + 2)]
				buf := bytes.NewReader(lengthB)
				var length uint16
				binary.Read(buf, binary.BigEndian, &length)
				deb += 2
				mess := string(bufR[deb:(deb + int(length))])
				if debugD {
					fmt.Println("date ", date)
					fmt.Println("hash ", hash)
					fmt.Println("length ", length, lengthB)
					fmt.Println("mess ", mess)
				}
				deb += int(length)
				if hash[0] == 0 {
					fmt.Printf("message datant du %v, %v\n\n", date, mess)
				} else {
					fmt.Printf("message datant du %v, repondant a %v, %v\n\n", date, hash, mess)
				}
			} else { // bufR est un noeud
				max := int(n) + deb - 32
				deb += 1
				// ajout de tous les noeud de bufR
				for max > deb {
					if debugD {
						fmt.Println("\nhash noeud ", bufR[deb:deb+32])
					}
					if notInArbre(bufR[deb:deb+32], messArbre) {
						messArbre = append(messArbre, bufR[deb:deb+32])
						hashArbre = append(hashArbre, bufR[deb:deb+32])
					}
					deb += 32
				}
			}
		}
	}
}

// demande de message/datum via hash
func getDatumMess(pair jsonPeer, hash []byte) []byte {
	if debugD {
		fmt.Println("getdatum please")
	}

	// envoie getDatum a toutes les adresses de pair enregistre dans le serveur
	bufR := make([]byte, 1096)
	nbAdd := len(pair.Addresse)
	indxdep := 0
	if nbAdd >= 3 {
		indxdep = nbAdd - 2
	}
	for i := indxdep; i < len(pair.Addresse); i++ {
		addrconn := fmt.Sprintf("[%s]:%d", pair.Addresse[i].Host, pair.Addresse[i].Port)
		if debugD {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
			fmt.Printf("addrconn %s \n", addrconn)
		}
		// envoie de bufE
		adr2, err := net.ResolveUDPAddr("udp", addrconn)
		if err != nil {
			fmt.Printf("resolve")
			log.Fatal(err)
		}

		tps := 2
		brk1 := 0 // == 1 recu datum ou nodatum
		notD := false
		var bufE []byte
		for brk1 != 1 {
			if notD == false {
				bufE = rempMess(2, 32, hash, vide)
				if debugD {
					fmt.Println("\n\ngetdatum mess : dans bufE ", bufE)
				}
				_, err = conn.WriteTo(bufE, adr2)
				if err != nil {
					fmt.Println("write")
					log.Fatal(err)
				}
				fmt.Println("demande getdatum envoyer!")
			}

			// prepare bufrecevoir pour ecrire le message recu dedans
			conn.SetReadDeadline(time.Now().Add(time.Duration(tps) * time.Second))
			_, _, err = conn.ReadFrom(bufR)
			if err != nil {
				fmt.Println("Attente\n")
				tps = tps * 2
				if tps >= 32 {
					tps = 2
				}
			} else if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 131) {
				// verif que cest bien un datumreply (donc type 130 ou 131 nodatum) et id du datum = id du getdatum
				// verif la valeur du hash
				if bytes.Compare(hash, bufR[7:39]) == 0 {
					if debugD {
						fmt.Println("meme hash no")
					}
					fmt.Println("recu NOdatum correct\n")
					return nil
				}
				brk1 += 1
				tps = 2
			} else if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 130) {
				// verif la valeur du hash
				if bytes.Compare(hash, bufR[7:39]) == 0 {
					if debugD {
						fmt.Println("meme hash datum")
					}
					fmt.Println("recu datum correct")
				}
				if debugD {
					fmt.Println("le mess dans bufR ", bufR)
				}
				brk1 += 1
				tps = 2
			} else if bufR[4] == 254 {
				if debugD {
					fmt.Println("message erreur")
					fmt.Println(string(bufR[7:]))
					fmt.Println("le mess dans bufR ", bufR)
				}
				notD = true
			} else {
				if debugD {
					fmt.Println("ERREUR !!!!!!!!")
					fmt.Println("le mess dans bufR ", bufR)
					fmt.Println("le mess dans bufE ", bufE)
				}
				notD = true
			}
		}
		if myIP == 4 {
			i++
		}
	}
	return bufR
}

// pas le hash demande dans a (arbreMerkle)
func noDatumMess(adr net.Addr, bufR []byte) {
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

// trouver le hash demande dans a (arbreMerkle)
func datumMess(adr net.Addr, bufR []byte) {
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

// demande de traverser de nat au serveur
func nat(adr *net.UDPAddr) {
	fmt.Println("demande de nat")
	// je suis A je veux me connecter a B
	// envoie un message non soliciter au serveur nat traversal client 132
	// implementer dans waitwait le cas si je recoit le nat transerval server 133
	// alors je doit reagir en envoyant helloreply a A
	// un peu plus tard A (moi) envoie une requete hello a B
	if debugN {
		fmt.Println("adr ", adr)
		fmt.Println("adrIP taille ", len(adr.IP))
		for i := 0; i < len(adr.IP); i++ {
			fmt.Printf("adrIP %d %v\n", i, adr.IP[i])
		}
		fmt.Println("adrPort ", adr.Port)
	}
	bufport := make([]byte, 2)
	binary.BigEndian.PutUint16(bufport, uint16(adr.Port))
	var buf []byte
	var bufE []byte
	if adr.IP[0] == 0 && adr.IP[1] == 0 { // ipv4
		buf = make([]byte, 6)
		// remplissage de ladresse et port de adr
		for i := 0; i < 4; i++ {
			if debugN {
				fmt.Println(adr.IP[i+len(adr.IP)-4])
			}
			buf[i] = adr.IP[i+len(adr.IP)-4]
		}
		buf[4] = bufport[0]
		buf[5] = bufport[1]

		// envoie de bufE au serveur
		bufE = rempMess(132, 6, buf, vide)
		serverADDRESS := fmt.Sprintf("[%s]:%d", serveur.Addresse[0].Host, serveur.Addresse[0].Port)
		server, err := net.ResolveUDPAddr("udp", serverADDRESS)
		if err != nil {
			fmt.Println("Resolveudp NAT")
			log.Fatal(err)
		}
		if debug {
			fmt.Println("serveur ip", server.IP)
			fmt.Println("serveur port", server.Port)
		}
		_, err = conn.WriteTo(bufE, server)
		if err != nil {
			fmt.Printf("write\n")
			log.Fatal(err)
		}
	} else { // ipv6
		buf = make([]byte, 18)
		// remplissage de ladresse et port de adr
		for i := 0; i < 16; i++ {
			if debugN {
				fmt.Println("tchooo ", i)
				fmt.Println(adr.IP[i+len(adr.IP)-16])
			}
			buf[i] = adr.IP[i+len(adr.IP)-16]
		}
		buf[16] = bufport[0]
		buf[17] = bufport[1]

		// envoie de bufE au serveur
		bufE = rempMess(132, 18, buf, vide)
		serverADDRESS := fmt.Sprintf("[%s]:%d", serveur.Addresse[1].Host, serveur.Addresse[1].Port)
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
	}

	if debugN {
		fmt.Println("bufport", bufport)
		fmt.Println("mess buf nat ", buf)
		fmt.Println("mess buf nat taille ", len(buf))
		fmt.Println("port ", buf[4], buf[5])
		fmt.Println("mess bufE nat ", bufE)
	}

	fmt.Println("nat envoyer")
}

// recevoir un nat du serveur et envoie un helloreply a celui qui a demande
func natReceive(bufR []byte) {
	fmt.Printf("j'ai recu nat du serveur\n")
	fmt.Println("message recu ", bufR)

	// a qui envoyer le helloreply
	var port uint16
	adrtostring := "["
	if bufR[6] == 6 { // ipv4
		portByte := (bufR[11:13])
		fmt.Println(portByte)
		buf := bytes.NewReader(portByte)
		binary.Read(buf, binary.BigEndian, &port)
		fmt.Printf("port4 : %d\n", port)
		for i := 0; i < 4; i++ {
			if i == 3 {
				adrtostring = fmt.Sprintf("%s%d]", adrtostring, bufR[7+i])
			} else {
				adrtostring = fmt.Sprintf("%s%d.", adrtostring, bufR[7+i])
			}
		}
	} else if bufR[6] == 18 { // ipv6
		portByte := (bufR[23:25])
		buf := bytes.NewReader(portByte)
		binary.Read(buf, binary.BigEndian, &port)
		fmt.Printf("port6 : %d\n", port)
		for i := 0; i < 16; i += 2 {
			adr := hex.EncodeToString(bufR[7+i : 7+2+i])
			if i == 14 {
				adrtostring = fmt.Sprintf("%s%s]", adrtostring, adr)
			} else {
				adrtostring = fmt.Sprintf("%s%s:", adrtostring, adr)
			}
		}
	}

	// envoie du helloreply
	adrtostring = fmt.Sprintf("%s:%d", adrtostring, port)
	fmt.Printf("adr : %s\n", adrtostring)
	adr2, err := net.ResolveUDPAddr("udp", adrtostring)
	if err != nil {
		fmt.Println("resolve wait")
		log.Fatal(err)
	}
	helloreply(adr2, bufR)
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

	var pair jsonPeer
	err = json.Unmarshal([]byte(body), &pair)
	if err != nil {
		log.Fatal(err)
	}

	if debugP {
		fmt.Printf("name : %s \n", pair.Name)
		for i := 0; i < len(pair.Addresse); i++ {
			fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)

		}
	}
	return pair
}

func choix(mess string, scanner *bufio.Scanner) {
	// fmt.Printf("Pour poster un message, taper 1\nPour faire une requete, taper 2\n")
	// if scanner.Scan() {
	// 	line := scanner.Text()
	switch mess {
	case "1": // message
		fmt.Printf("Pour écrire un message, taper 1\nPour avoir la liste de vos messages, taper 2\n")
		if scanner.Scan() {
			line := scanner.Text()
			switch line {
			case "1":
				fmt.Printf("Taper votre message\n")
				if scanner.Scan() {
					line := scanner.Text()
					ajoutMess(line, vide)
				}
				break
			case "2":
				affichageArbre()
				break
			}
		}
		break
	case "2": // requete
		fmt.Printf("Pour se connecter a un pair, taper 1\nPour faire une demande de racine (rootrequest), taper 2\n")
		if scanner.Scan() {
			line := scanner.Text()
			switch line {
			case "1":
				fmt.Printf("Taper le nom du pair a contacter parmis: \n")
				liste := chercherPairs()
				fmt.Printf("%s\n", liste)
				if scanner.Scan() {
					pairdemander := scanner.Text()
					if liste != "" {
						justhelloplease = true // car on vas envoyer des mssg
						pair = chercherPair(pairdemander)
						fmt.Printf("name : %s \n", pair.Name)
						i := 0
						for i = 0; i < len(pair.Addresse); i++ {
							fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
						}
					}
					hello(pair)
					justhelloplease = false
				}

				break
			case "2":
				if len(pair.Name) == 0 {
					fmt.Println("Connecter vous d'abord a un pair !!")
				} else {
					justhelloplease = true // car on vas envoyer des mssg
					hash := rootrequestmess(pair)
					fmt.Println("\nhash ", hash)
					fmt.Println()
					justhelloplease = false
					sortir := false
					for !sortir {
						fmt.Printf("Envoyer une demande de données (getdatum), taper 1\n Sinon pour sortir taper  2\n")
						if scanner.Scan() {
							rep := scanner.Text()
							switch rep {
							case "1":
								justhelloplease = true
								afficheDatum(pair)
								justhelloplease = false
								// fmt.Println("\ndata ", data)
								break
							case "2":
								sortir = true
								break
							default:
								fmt.Printf("Numero inconnu !")
								break
							}
						}
					}
				}
				break
			default:
				fmt.Printf("Numero inconnu !")
				break

			}
		}

		break
	default:
		fmt.Printf("Numero inconnu !")
		break
	}
	// }
}

func main() {
	arg1 := os.Args[1]
	if arg1 == "6" {
		if debugIP {
			fmt.Println("Vous avez ipv6")
		}
		myIP = 6
	}

	initialisationArbre()
	affichageArbre()

	ajoutMess("hello", vide)
	time.Sleep(1 * time.Second)
	ajoutMess("guten tag", vide)
	// time.Sleep(1 * time.Second)
	ajoutMess("bonjouuuur", vide)
	time.Sleep(1 * time.Second)
	affichageArbre()

	session()
	wg.Add(1)
	go waitwaitmessages()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Printf("Pour envoyer un message (1), une requete (2), ecrire dans le terminal le numero correspondant, sinon vous etes en attente de message.\n")
		if scanner.Scan() {

			line := scanner.Text()
			fmt.Printf("%s\n", line)
			choix(line, scanner)
			fmt.Println("*********************************************************************************************")
		}

	}

	// envoie de requete de maniere manuelle

	// justhelloplease = true // car on vas envoyer des mssg
	// // wg.Add(1)
	// // go waitwaitmessages()
	// fmt.Println("*********************************************************************************************")
	// liste := chercherPairs()
	// fmt.Printf("liste : %s\n", liste)
	// var pair jsonPeer
	// if liste != "" {
	// 	pair = chercherPair("bet")
	// 	fmt.Printf("name : %s \n", pair.Name)
	// 	i := 0
	// 	for i = 0; i < len(pair.Addresse); i++ {
	// 		fmt.Printf("ip : %s \n port: %d\n", pair.Addresse[i].Host, pair.Addresse[i].Port)
	// 	}
	// 	// adr = fmt.Sprintf("[%s]:%d", pair.Addresse[i-1].Host, pair.Addresse[i-1].Port)
	// }
	// fmt.Println("*********************************************************************************************")
	// time.Sleep(8 * time.Second)
	// hello(pair)
	// fmt.Println("hello ok lelellclkzc,nfvvrybzvjzrbvnc eaqnk")
	// hash := rootrequestmess(pair)
	// fmt.Println("\nhash ", hash)
	// fmt.Println()
	// data := getDatumMess(pair, hash)
	// fmt.Println("\ndata ", data)
	// fmt.Println("************************\n\n")
	// afficheDatum(pair)
	// time.Sleep(5 * time.Second)
	// fmt.Println("\n************************")
	// afficheDatum(pair)

	// justhelloplease = false // on se met en lecture on a fini nos requete
	// fmt.Println("*********************************************************************************************")
	// fmt.Println("requete fini ...MERCI")

	wg.Wait()
	defer conn.Close()

}
