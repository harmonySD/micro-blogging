package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
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

func main() {}
