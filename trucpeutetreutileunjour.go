// package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"
)

func helloreplyServeur(bufR []byte, conn net.PacketConn, name string) {

	bufE := rempMess(name, 128, bufR)
	if debug {
		fmt.Println("le mess dans bufE ", bufE)
	}
	_, err := conn.WriteTo(bufE, adr2)
	if err != nil {
		fmt.Printf("write\n")
		log.Fatal(err)
	}
	if debug {
		fmt.Printf("helloReply envoye\n")
	}
}

// fonction qui envoie un hello et attend un helloreply
func helloServeur(name string, conn net.PacketConn, message []jsonMessage) {
	buf := make([]byte, 1)
	bufE := rempMess(name, 0, buf)
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
		i := 1
		// for i == 1 {
		// 	bufR := make([]byte, 256)

		// 	_, _, err = conn.ReadFrom(bufR)
		// 	if err != nil {
		// 		fmt.Printf("read\n")
		// 		log.Fatal(err)
		// 	}
		// 	if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
		// 		fmt.Printf("helloReply\n")
		// 		if debug {
		// 			fmt.Println("le mess dans bufR ", bufR)
		// 		}
		// 		i = 0
		// 	}
		// 	if bufR[4] == 254 {
		// 		fmt.Printf("erreur\n")
		// 		fmt.Println(string(bufR[7:]))
		// 		i = 0
		// 	}
		// }
		for i == 1 {
			// fmt.Printf("\n\n\nwhile\n")
			fmt.Printf("\n\n\n")
			bufR := make([]byte, 256)

			_, _, err = conn.ReadFrom(bufR)
			if (bytes.Compare(bufR[0:4], bufE[0:4]) == 0) && (bufR[4] == 128) {
				fmt.Printf("helloReply\n")
				if debug {
					fmt.Println("le mess dans bufR ", bufR)
				}

			}
			if err != nil {
				fmt.Printf("read\n")
				log.Fatal(err)
			}
			if bufR[4] == 0 {
				fmt.Printf("hello\n")
				if debug {
					fmt.Println("le mess dans bufR ", bufR)
				}
				bufE := rempMess(name, 128, bufR)
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
				i = 0
			}
			if bufR[4] == 254 {
				fmt.Printf("erreur\n")
				fmt.Println(string(bufR[7:]))
				i = 0
			}
		}

	}

}

// fonction qui envoie un hello et attend un helloreply
func hello(name string, pair string) {
	pairJson := chercherPair(pair)

	fmt.Printf("hello\n")
	port := fmt.Sprintf(":%d", pairJson.Addresse[0].Port)
	addrconn := fmt.Sprintf("[%s]:%d", pairJson.Addresse[0].Host, pairJson.Addresse[0].Port)
	conn, err := net.ListenPacket("udp", port)
	if err != nil {
		fmt.Printf("listen\n")
		log.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 1)
	bufE := rempMess(name, 0, buf)
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

// fonction qui envoie un hello et attend un helloreply
// si forServeur ==1 cets quon est dans le cas handshake serveur
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

func main() {}
