package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

const nom = "gogogo"
const signature = ""
const id = "id"
const address = "https://jch.irif.fr:8443/udp-address"
const Addr_liste_pair = "https://jch.irif.fr:8443/peers"

const urlPost = "https://jch.irif.fr:8443/register"

type socketServer []struct {
	Ip   string `json:"ip"`
	Port int64  `json:"port"`
}

const DATAGRAM_MIN_LENGTH = 4 + 1 + 2 + 4 + 1

func construction_packet() ([]byte, int) {
	nom := []byte(nom)
	nom_length := len(nom)
	// siganature := []byte(signature)
	// signature_length := len(siganature)
	length := 5 + nom_length
	datagram_length := 4 + 1 + 2 + length

	// corps_length := 4 + nom_length + signature_length
	// var datagram_type byte = 0
	var datagram_flags byte = 0

	datagram := make([]byte, datagram_length)

	// copy(datagram[:4], []byte(id)) // The first 4 bytes: for the id
	datagram[0] = 0
	datagram[1] = 0
	datagram[2] = 0
	datagram[3] = 9
	datagram[4] = 0

	lenghtbyte := make([]byte, 2)
	binary.BigEndian.PutUint16(lenghtbyte, uint16(length))
	datagram[5] = lenghtbyte[0]
	datagram[6] = lenghtbyte[1]

	datagram[7] = datagram_flags
	datagram[8] = datagram_flags
	datagram[9] = datagram_flags
	datagram[10] = datagram_flags
	datagram[11] = byte(nom_length)

	copy(datagram[12:], nom)
	i := 12
	j := 12
	k := 0
	for i < j+nom_length {
		datagram[i] = nom[k]
		i++
		k++
	}

	// bite_signature := 12 + nom_length

	// copy(datagram[bite_signature:], siganature)
	fmt.Println(datagram)

	return datagram, datagram_length
}

func getHttpResponse(client *http.Client, requestUrl string) []byte {
	fmt.Printf("HTTP GET REQUEST : %v \n", requestUrl)

	// func http.NewRequest(method string, url string, body io.Reader) (*http.Request, error)
	req, errorMessage := http.NewRequest("GET", requestUrl, nil)
	if errorMessage != nil {
		// func log.Fatal(v ...any)
		// Fatal is equivalent to Print() followed by a call to os.Exit(1).
		log.Fatal("http.NewRequest() function : ", errorMessage)
	}

	// func (*http.Client).Do(req *http.Request) (*http.Response, error)
	r, errorMessage := client.Do(req)
	if errorMessage != nil {
		log.Fatal("client.Do() function : ", errorMessage)
	}

	// func ioutil.ReadAll(r io.Reader) ([]byte, error)
	body, errorMessage := ioutil.ReadAll(r.Body)
	// func (io.Closer).Close() error
	r.Body.Close()

	if errorMessage != nil {
		log.Fatal("ioutil.ReadAll() function : ", errorMessage)
	}

	return body
}

func main() {

	// requête Get pour obtenir l'address de socket du serveur

	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // This is a code for pedagogical purposes !
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	body := getHttpResponse(client, address)

	var sock socketServer

	if err := json.Unmarshal(body, &sock); err != nil {
		fmt.Println("can not unmarshal json")
	}

	var ipv4 = sock[0].Ip
	var portv4 = sock[0].Port

	postBody, _ := json.Marshal(map[string]string{
		"Name": nom,
	})

	responseBody := bytes.NewBuffer(postBody)

	resp, err := http.Post(urlPost, "application/json", responseBody)
	if err != nil {
		fmt.Println("error in http.Post")
	}

	fmt.Println("response Status:", resp.Status)

	socket_address := fmt.Sprintf("%s:%d", ipv4, portv4)
	fmt.Println("udp addresse", socket_address)

	if err != nil {
		fmt.Println("error in net.ResolveUDPAddr")
	}

	if err != nil {
		fmt.Println("error in net.ListenPacket")
	}

	//Connection UDp

	port := fmt.Sprintf(":%d", 7880)
	fmt.Printf("port : %s\n", port)
	conn, err := net.ListenPacket("udp", port)

	addrconn := fmt.Sprintf("[%s]:%d", sock[0].Ip, sock[0].Port)
	addr2, err := net.ResolveUDPAddr("udp", addrconn)

	if err != nil {
		// func log.Fatal(v ...any)
		// Fatal is equivalent to Print() followed by a call to os.Exit(1).
		log.Fatal("Function net.Dial() : ", err)
	}

	buffer, _ := construction_packet()
	fmt.Printf("buffer send : %x\n", buffer)
	_, err = conn.WriteTo(buffer, addr2)
	bufR := make([]byte, 256)
	fmt.Println("***********************")

	_, _, err = conn.ReadFrom(bufR)
	fmt.Println(bufR)
	fmt.Println("***********************")
	// if err != nil {
	// 	fmt.Println("WriteTo")
	// }

	// HelloReply := make([]byte, datagram_length)

	// _, err = bufio.NewReader(connection).Read(HelloReply)

	// if err != nil {
	// 	fmt.Println("ReadFromUDP")
	// }

	// fmt.Printf("type de helloReply %v", HelloReply[5])
	//}

	// liste de pairs enregistre aupres du serveur

	reponse2, err := http.Get(Addr_liste_pair)
	if err != nil {
		fmt.Printf("Error in Get %s", err)
		return
	}

	body2, err := io.ReadAll(reponse2.Body)
	if err != nil {
		fmt.Println("error in io.ReadAll")
	}
	fmt.Printf("\n %v", string(body2))
}
