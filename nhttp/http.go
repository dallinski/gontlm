package nhttp

import (
	"encoding/base64"
	"github.com/dallinski/gontlm"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
)

type Transport struct {
	Domain   string
	User     string
	Password string
	conn     *httputil.ClientConn
	host     string
}

var encBase64 = base64.StdEncoding.EncodeToString
var decBase64 = base64.StdEncoding.DecodeString

func cloneRequest(req *http.Request) *http.Request {
	r2 := *req
	r2.Header = http.Header{}
	for k, v := range req.Header {
		r2.Header[k] = v
	}
	return &r2
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Host != t.host {
		if t.conn != nil {
			t.conn.Close()
		}

		t.host = req.Host

		host, port, err := net.SplitHostPort(t.host)
		if err != nil {
			port = "80"
		}

		sock, err := net.Dial("tcp", net.JoinHostPort(host, port))

		if err != nil {
			return nil, err
		}

		t.conn = httputil.NewClientConn(sock, nil)
		req.Header.Add("Authorization", "NTLM "+encBase64(ntlm.Negotiate()))
	}

	r, _ := http.NewRequest("POST", req.URL.String(), strings.NewReader(""))
	r.Header.Add("Authorization", "NTLM "+encBase64(ntlm.Negotiate()))
	resp, err := t.conn.Do(r)
	// resp, err := t.conn.Do(req)

	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		withNTLMfront := resp.Header.Get("Www-Authenticate")
		temp := strings.Replace(withNTLMfront, "NTLM ", "", -1)
		chlg, err := decBase64(temp)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		auth, err := ntlm.Authenticate(chlg, t.Domain, t.User, t.Password)
		if err != nil {
			return nil, err
		}

		req.Header.Set("Authorization", "NTLM "+encBase64(auth))
		req.Header.Add("content-type", "text/xml")
		resp, err = t.conn.Do(req)
	}

	return resp, err
}
