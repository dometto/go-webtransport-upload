package main

import (
    "fmt"
    "bufio"
    "net/http"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
    "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
    "math/big"
    "time"
    "strings"
	"encoding/binary"
	"context"
    "os"
    "io"
	_ "embed"
	"flag"

    //"github.com/quic-go/quic-go"
    "github.com/quic-go/quic-go/http3"
    "github.com/quic-go/webtransport-go"
)

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getTLSConf(start, end time.Time) (*tls.Config, error) {
	cert, priv, err := generateCert(start, end)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  priv,
			Leaf:        cert,
		}},
	}, nil
}
func generateCert(start, end time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, nil, err
	}
	serial := int64(binary.BigEndian.Uint64(b))
	if serial < 0 {
		serial = -serial
	}
	certTempl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{},
		NotBefore:             start,
		NotAfter:              end,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	ca, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return nil, nil, err
	}
	return ca, caPrivateKey, nil
}

func formatByteSlice(b []byte) string {
	s := strings.ReplaceAll(fmt.Sprintf("%#v", b[:]), "[]byte{", "[")
	s = strings.ReplaceAll(s, "}", "]")
	return s
}

func tokenGenerator(len int) string {
	b := make([]byte, len)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func handleAuth(clientToken string, token string, w http.ResponseWriter) {
	// very basic auth
	fmt.Printf("Client token: %s\n", clientToken)
	if clientToken != token {
		fmt.Println("Authentication failed!")
		w.WriteHeader(500)
		return
	}
}

func runClient(domain string) {
	ctx := context.Background()

    reqHeaders := http.Header{
        "Upload-File-Name": {"test"},
    }
    
	d := webtransport.Dialer{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	_, wtSession, err := d.Dial(ctx, domain, reqHeaders)
	checkErr(err)

	stream, err := wtSession.OpenStreamSync(ctx)
	checkErr(err)

	_, err = stream.Write([]byte("Hi there"))
	checkErr(err)

        // Note that stream.Close() only closes the send side. This allows the
        // stream to receive the reply from the server.
	err = stream.Close()
	checkErr(err)

	bytes, err := io.ReadAll(stream)
	checkErr(err)

	fmt.Println("From server: " + string(bytes))
}

//go:embed index.html
var indexHTML string

func handleUpload(fName string, sess *webtransport.Session) {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    stream, err := sess.AcceptStream(ctx)
    checkErr(err)

    newFile, err := os.Create(fName)
    checkErr(err)
    defer newFile.Close()

    writer := bufio.NewWriterSize(newFile, 32*1024)
    defer writer.Flush()

    _, err = io.Copy(writer, stream)
    checkErr(err)

    fmt.Println("Uploaded File\n")
    select {
    case <-sess.Context().Done():
        fmt.Println("done")
    case <-time.After(5 * time.Second):
        fmt.Println("timed out waiting for the session to be closed")
    }
}

func runHTTPServer(certHash [32]byte, token string, clientServerUrl string) {
    mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Got connection on TCP")
		handleAuth(r.URL.Query().Get("token"), token, w)
        w.Header().Set("Content-Type", "text/html")
        content := strings.ReplaceAll(indexHTML, "%%CERTHASH%%", formatByteSlice(certHash[:]))
		content = strings.ReplaceAll(content, "%%TOKEN%%", token)
		content = strings.ReplaceAll(content, "%%SERVERURL%%", clientServerUrl)
        w.Write([]byte(content))
    })
	http.ListenAndServe("localhost:9090", mux)
}

func runServer(tlsConf *tls.Config, clientServerUrl string) {
	certHash := sha256.Sum256(tlsConf.Certificates[0].Leaf.Raw)
    fmt.Printf("Certificate hash: %x\n", certHash)

	token := tokenGenerator(32)
	fmt.Printf("Auth token: %s\n", token)
	go runHTTPServer(certHash, token, clientServerUrl)


	wmux := http.NewServeMux()
	wtServer := webtransport.Server{
        CheckOrigin: func(r *http.Request) bool { return true },
		H3: http3.Server{
			Addr:       "localhost:9090",
            Handler: wmux,
            // QUICConfig: &quic.Config{
            //     EnableDatagrams: true,
            // },
            TLSConfig: tlsConf,
		},
	}
    defer wtServer.Close()

	wmux.HandleFunc("/uploadFile", func(w http.ResponseWriter, r *http.Request) {
		handleAuth(r.URL.Query().Get("token"), token, w)

		conn, err := wtServer.Upgrade(w, r)
		if err != nil {
			fmt.Printf("upgrading failed: %s", err)
			w.WriteHeader(500)
			return
		}	
		fName := r.URL.Query().Get("fileName")
        fmt.Printf("File name: %s\n", fName)
        handleUpload(fName, conn)
	})

	err := wtServer.ListenAndServe()
	checkErr(err)
}

func getTLSConfFromFile(pem string, key string) *tls.Config {
	cert, err := tls.LoadX509KeyPair(pem, key)
	if err != nil {
		panic(err)
	}

    return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func main() {
	clientServerUrl := flag.String("client-server-url", "https://127.0.0.1:9090/uploadFile", "the URL to which the client should connect (can be a reverse proxy to the backend of this app).")
	useReadyCert := flag.Bool("use-existing-cert", false, "Use certificate.pem and certificate.key from the current dir")
	flag.Parse()

	var tlsConf *tls.Config

	if *useReadyCert == true {
		tlsConf = getTLSConfFromFile("certificate.pem", "certificate.key")
	} else {
		tlsConf, _ = getTLSConf(time.Now(), time.Now().Add(10*24*time.Hour))
	}
    runServer(tlsConf, *clientServerUrl)
}
