package main

import (
    "bytes"
	"crypto/rand"
	"crypto/rsa"
    "crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
    "fmt"
	"github.com/wayf-dk/pkcs11"
	"net/http"
    "net/http/httptest"
    "time"
)

func init() {
	keymap = make(map[string]aclmap)
	slotmap = make(map[string]pkcs11.ObjectHandle)

	initConfig()

	p = pkcs11.New(config["GOELEVEN_HSMLIB"])

	sem = make(chan Hsm, maxsessions)
	bginit()
    http.HandleFunc("/", handler)
}

func ExampleSignError() {

    params := request{
        "vMx1C2EMvOL6WubL+O48hcPUiDAXXrOonK/6o83LVhVCeCu/Vm567gyUzppUiC/egjeZg0JUh5GhFYVups1DM8n8H9zzTJjDvW5yfRwx3+EEnhLazjESokgKjykURJfQE487cEnyPyjcSe89McyBA92dhRlCUoSxfs17UjRptKcNm/5WOEQ4ahHyTnD7UnBOA2CMNUkRUEUzTF8FRF8bmMFzKXPpgC3K5CdmHC4z7hY9ThANfsfo2HOAFsTLOvfkeH3ZxJVg5dL28wZjsG9zV/2nfjFrkK8OoSm0GXa4wNPsstOHckLCcgBAOqYvk9P3UqWk8vBIUE5lWGOiW91qAA==",
//        "aGVqbWVkZGlnCg==",
        "CKM_RSA_PKCS",
        "",
        "sign",
        keymap["wildcard.test.lan.key"].sharedsecret,
    }

    payloadjson, _ := json.Marshal(params)

	payload := bytes.NewReader(payloadjson)

    r, _ := http.NewRequest("POST", "/wayfha/wildcard.test.lan.key", payload)
    r.RemoteAddr = "127.0.0.1"
    w := httptest.NewRecorder()

    time.Sleep(1 * time.Second) // wait for async init of service
    Log(http.DefaultServeMux).ServeHTTP(w, r)
    fmt.Printf("%d - %s", w.Code, w.Body.String())
    // Output:
    // 500 - Invalid Input
}

func ExampleSign() {

    params := request{
        "aGVqbWVkZGlnCg==",
        "CKM_RSA_PKCS",
        "",
        "sign",
        keymap["wildcard.test.lan.key"].sharedsecret,
    }

    payloadjson, _ := json.Marshal(params)

	payload := bytes.NewReader(payloadjson)

    r, _ := http.NewRequest("POST", "/wayfha/wildcard.test.lan.key", payload)
    r.RemoteAddr = "127.0.0.1"
    w := httptest.NewRecorder()

    time.Sleep(1 * time.Second) // wait for async init of service
    Log(http.DefaultServeMux).ServeHTTP(w, r)
    fmt.Printf("%d - %s", w.Code, w.Body.String())
    // Output:
    // 200 - {"signed":"PTwWtTP3PbIY4N6ss3iOHOcRS7xV+7mrkDKPXrkEpscyZhH6eGnSkljhJCpxhsIrtVnEjQ4VOI5AlMuf9cvwwG2XPeze18Is99E5XwwzynREt+rFiL9dpKoibYYuGMjTxr+qF44SDzzJP8sAwE42j7xBj81etxvN07s5TPV46BUGTGo87c2xiPLJ11n4r/6vUTGWFGdViAO5tnq5heKF0GcVDU3n6r3JXbfHe0sP+3AfJsVuWqayC2C1N49jmJgZLbhplRmhNabTRpEHzZHyaBkioQZ0Yf31kzuYSBemHnGpZv9MGwtjzUw7DsxwaZ9z/RNs7H5OhSoTdcGH1H4clg=="}
}

func ExampleDecrypt() {
    publickey := "MIIEbjCCA1agAwIBAgIRAOpBhouRJl1gj7JWKYJLGbAwDQYJKoZIhvcNAQEFBQAwNjELMAkGA1UEBhMCTkwxDzANBgNVBAoTBlRFUkVOQTEWMBQGA1UEAxMNVEVSRU5BIFNTTCBDQTAeFw0xMzA5MDIwMDAwMDBaFw0xNjA5MjAyMzU5NTlaMD4xITAfBgNVBAsTGERvbWFpbiBDb250cm9sIFZhbGlkYXRlZDEZMBcGA1UEAxMQYmV0YXdheWYud2F5Zi5kazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMI6ZXEBejtl25Uz1r32GrtmyTjhgbNduHDlmMeuGIVFgVOMtwQDUvlvFOG8H9paJ6xRrHuTw+QktZBBcEEkPOdnMekmtvgucc+lPuHdXlUS6gkd+iHdT5WRNnwg+Uwl1X/45LcaUhXAO2zRsYC3aiTaUmjtEz9YHXgdnaMj4pOoCpLCYWp0UkxzUjd2Js3YdMgn6TDYZdk0YTiZ7SvipSoP13hNgo/vP7uziDwmTTP6H4KkOdd98WX08hgmk6z4BeaeYzE82Hp7DnMcW5Mk8SUNSf5E0d5vcWxCr2mUfH/nZlS9SrzE5qBqRUGnLNZOvAlOX00Digxl4lc4xhPKaNcCAwEAAaOCAW0wggFpMB8GA1UdIwQYMBaAFAy9k2gM896ro0lrKzdXR+qQ47ntMB0GA1UdDgQWBBQocIgUSR/fr0wPPkXxQfmSirPr3TAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIgYDVR0gBBswGTANBgsrBgEEAbIxAQICHTAIBgZngQwBAgEwOgYDVR0fBDMwMTAvoC2gK4YpaHR0cDovL2NybC50Y3MudGVyZW5hLm9yZy9URVJFTkFTU0xDQS5jcmwwbQYIKwYBBQUHAQEEYTBfMDUGCCsGAQUFBzAChilodHRwOi8vY3J0LnRjcy50ZXJlbmEub3JnL1RFUkVOQVNTTENBLmNydDAmBggrBgEFBQcwAYYaaHR0cDovL29jc3AudGNzLnRlcmVuYS5vcmcwGwYDVR0RBBQwEoIQYmV0YXdheWYud2F5Zi5kazANBgkqhkiG9w0BAQUFAAOCAQEAAg7GQxtHHvrksFK3CIb+4F8Aj34GT7H45rfgZPcJO8zpxc5o3kNi+ag4+YUChkNKDRgKuYyspOgJpn2eEhGly2GvD1upFXUEZV28LqbErHxzpUA6U/+VUV1pRlZIrhakAUkzZavxzgbm0W9OxMc2qcJo6aCfl4LT7D6V6r62iYy+iE4xNpKlnP5Yd32vnqlKTiCSvXWWhCDbgIoijZ+EIF9J2V0dYS3PvM2Xj0z9DGNxXLzaVzlsOCAFVo61I4PZDO1YbgWKYn7CrqNjW/XW5hb4W0zayOFfslardt6XR+erSsNB6zxf6vjRpvQNio9CRxwQwFBEHlAq5Ct8csAnNQ=="

	block, _ := base64.StdEncoding.DecodeString(publickey)
    pk, err := x509.ParseCertificate(block)
    if err != nil {
        panic(err)
    }

    ciphertext, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pk.PublicKey.(*rsa.PublicKey), []byte("anton banton"), nil)
    if err != nil {
        panic(err)
    }

    cipher := base64.StdEncoding.EncodeToString(ciphertext)

    params := request{
        cipher,
        "CKM_RSA_PKCS_OAEP",
        "CKM_SHA_1",
        "decrypt",
        keymap["betawayf.wayf.dk.key"].sharedsecret,
    }

    payloadjson, _ := json.Marshal(params)

	payload := bytes.NewReader(payloadjson)

    r, _ := http.NewRequest("POST", "/wayfha/betawayf.wayf.dk.key", payload)
    r.RemoteAddr = "127.0.0.1"
    w := httptest.NewRecorder()

    time.Sleep(1 * time.Second) // wait for async init of service
    Log(http.DefaultServeMux).ServeHTTP(w, r)
	type Res struct {
		Result string `json:"signed"`
	}
    b := Res{}
	err = json.Unmarshal(w.Body.Bytes(), &b)
	res, _ := base64.StdEncoding.DecodeString(b.Result)
    fmt.Printf("%s\n", res)

    // Output:
    // anton banton
}