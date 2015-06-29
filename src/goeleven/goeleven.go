package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wayf-dk/pkcs11"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type Hsm struct {
	session pkcs11.SessionHandle
	obj     pkcs11.ObjectHandle
	used    int
	started time.Time
	sessno int
}

var currentsessions int
var hsm1 Hsm
var sem chan Hsm
var pguard sync.Mutex
var p *pkcs11.Ctx
var config = map[string]string{
	"GOELEVEN_HSMLIB":        "",
	"GOELEVEN_INTERFACE":     "localhost:8080",
	"GOELEVEN_SLOT":          "",
	"GOELEVEN_SLOT_PASSWORD": "",
	"GOELEVEN_KEY_LABEL":     "",
	"GOELEVEN_SHAREDSECRET":  "",
	"GOELEVEN_MINSESSIONS":   "1",
	"GOELEVEN_MAXSESSIONS":   "1",
	"GOELEVEN_MAXSESSIONAGE": "1000000",
	"GOELEVEN_DEBUG":         "false",
	"SOFTHSM_CONF":           "softhsm.conf",
}
var xauthlen = map[string]int{
	"min": 12,
	"max": 32,
}

func main() {
	currentsessions = 0
	//wd, _ := os.Getwd()
	initConfig()
	p = pkcs11.New(config["GOELEVEN_HSMLIB"])
	p.Initialize()
	go handlesessions()
	http.HandleFunc("/", handler)
	http.ListenAndServe(config["GOELEVEN_INTERFACE"], nil)
}

// initConfig read several Environment variables and based on them initialise the configuration
func initConfig() {
	envFiles := []string{"SOFTHSM_CONF", "GOELEVEN_HSMLIB"}

	// Load all Environments variables
	for k, _ := range config {
		if os.Getenv(k) != "" {
			config[k] = os.Getenv(k)
		}
	}
	// All variable MUST have a value but we can not verify the variable content
	for k, _ := range config {
		if isdebug() {
			// Don't write PASSWORD to debug
			if k == "GOELEVEN_SLOT_PASSWORD" {
				debug(fmt.Sprintf("%v: xxxxxx\n", k))
			} else {
				debug(fmt.Sprintf("%v: %v\n", k, config[k]))
			}
		}
		if config[k] == "" {
			exit(fmt.Sprintf("Problem with %s", k), 2)
		}
	}

	// Check file exists
	for _, v := range envFiles {
		_, err := os.Stat(config[v])
		if err != nil {
			exit(fmt.Sprintf("%s %s", v, err.Error()), 2)
		}
	}
	// Test XAUTH enviroment
	_, err := sanitizeXAuth(config["GOELEVEN_SHAREDSECRET"])
	if err != nil {
		exit(fmt.Sprintf("GOELEVEN_SHAREDSECRET: %v", err.Error()), 2)
	}
}

func handlesessions() {
	// String->int64->int convert
	max, _ := strconv.ParseInt(config["GOELEVEN_MAXSESSIONS"], 10, 0)
	var maxsessions int = int(max)
	sem = make(chan Hsm, maxsessions)
	for currentsessions < maxsessions {
		currentsessions++
		sem <- inithsm(currentsessions)
	}
	debug(fmt.Sprintf("sem: %v\n", len(sem)))
}

// Check if the X-Auth string are safe to use
func sanitizeXAuth(insecureXAuth string) (string, error) {
	if len(insecureXAuth) >= xauthlen["min"] && len(insecureXAuth) <= xauthlen["max"] {
		return insecureXAuth, nil
	}
	return "", errors.New("X-AUTH do not complies with the defined rules")
}

// Client authenticate/authorization
func authClient(sharedkey string, slot string, keylabel string) error {
	//  Check sharedkey
	if sharedkey != config["GOELEVEN_SHAREDSECRET"] {
		return errors.New("Shared secret not match")
	}
	//  Check slot nummer
	if slot != config["GOELEVEN_SLOT"] {
		return errors.New("Slot number not match")
	}
	//  Check key aliases/label
	if keylabel != config["GOELEVEN_KEY_LABEL"] {
		return errors.New("Key label not match")
	}
	// client ok
	return nil
}

// TODO: Cleanup
// TODO: Documentation
// TODO: Error handling
/*
 * If error then send HTTP 500 to client and keep the server running
 *
 */
func handler(w http.ResponseWriter, r *http.Request) {
	var err error
	var validPath = regexp.MustCompile("^/(\\d+)/([a-zA-Z0-9]+)/sign$")
	mSlot := validPath.FindStringSubmatch(r.URL.Path)[1]
	mKeyAlias := validPath.FindStringSubmatch(r.URL.Path)[2]

	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)

	// Parse JSON
	//var b struct { Data,Mech string }
	var b map[string]interface{}
	err = json.Unmarshal(body, &b)
	if err != nil {
		http.Error(w, "Invalid input", 500)
		fmt.Printf("json.unmarshall: %v\n", err.Error())
		return
	}
	data, err := base64.StdEncoding.DecodeString(b["data"].(string))
	if err != nil {
		http.Error(w, "Invalid input", 500)
		fmt.Printf("DecodeString: %v\n", err.Error())
		return
	}

	// Client auth
	err = authClient(b["sharedkey"].(string), mSlot, mKeyAlias)
	if err != nil {
		http.Error(w, "Invalid input", 500)
		fmt.Printf("authClient: %v\n", err.Error())
		return
	}

	sig, err := signing(data)
	if err != nil {
		http.Error(w, "Invalid output", 500)
		fmt.Printf("signing: %v\n", err.Error())
		return
	}
	sigs := base64.StdEncoding.EncodeToString(sig)
	type Res struct {
		Slot   string `json:"slot"`
		Mech   string `json:"mech"`
		Signed string `json:"signed"`
	}
	res := Res{mSlot, "mech", sigs}
	json, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "Invalid output", 500)
		fmt.Printf("json.marshall: %v\n", err.Error())
		return
	}
	fmt.Fprintf(w, "%s\n\n", json)
}

// TODO: Cleanup
// TODO: Documentation
func inithsm(sessno int) Hsm {
	pguard.Lock()
	defer pguard.Unlock()
    slot, _ := strconv.ParseUint(config["GOELEVEN_SLOT"], 10, 32)

	slots, _ := p.GetSlotList(true)
	fmt.Printf("slots: %v\n", slots)

    fmt.Printf("slot: %v\n", slot)
    session, e := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION )

    if e != nil {
        panic(fmt.Sprintf("Failed to open session: %s\n", e.Error()))
    }

	p.Login(session, pkcs11.CKU_USER, config["GOELEVEN_SLOT_PASSWORD"])

	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, config["GOELEVEN_KEY_LABEL"]), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	if e := p.FindObjectsInit(session, template); e != nil {
		panic(fmt.Sprintf("Failed to init: %s\n", e.Error()))
	}
	obj, b, e := p.FindObjects(session, 2)

	debug(fmt.Sprintf("Obj %v\n", obj))
	if e != nil {
		panic(fmt.Sprintf("Failed to find: %s %v\n", e.Error(), b))
	}
	if e := p.FindObjectsFinal(session); e != nil {
		panic(fmt.Sprintf("Failed to finalize: %s\n", e.Error()))
	}
	debug(fmt.Sprintf("found keys: %v\n", len(obj)))
	if len(obj) == 0 {
		panic("should have found two objects")
	}

	fmt.Printf("hsm initialized new: %#v\n", obj[0])

	return Hsm{session, obj[0], 0, time.Now(), sessno}
}

// TODO: Cleanup
// TODO: Documentation
func signing(data []byte) ([]byte, error, int) {
	// Pop HSM struct from queue
	s := <-sem
	s.used++
	if s.used > 10000 || time.Now().Sub(s.started) > 1000*time.Second {
		p.Logout(s.session)
		p.CloseSession(s.session)
		//p.Finalize()
		//p.Destroy()
		s = inithsm(s.sessno)
	}
	fmt.Printf("hsm: %v\n", s)
	//    p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, s.obj)
	p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, s.obj)
	sig, err := p.Sign(s.session, data)
	fmt.Printf("err: %v\n", err)

	// Push HSM struct back on queue
	sem <- s
	return sig, nil, s.sessno
}

// Utils

func debug(messages string) {
	if config["GOELEVEN_DEBUG"] == "true" {
		fmt.Print(messages)
	}
}

// Standard function to test for debug mode
func isdebug() bool {
	if config["GOELEVEN_DEBUG"] == "true" {
		return true
	} else {
		return false
	}
}

func exit(messages string, errorCode int) {
	// Exit code and messages based on Nagios plugin return codes (https://nagios-plugins.org/doc/guidelines.html#AEN78)
	var prefix = map[int]string{0: "OK", 1: "Warning", 2: "Critical", 3: "Unknown"}

	// Catch all unknown errorCode and convert them to Unknown
	if errorCode < 0 || errorCode > 3 {
		errorCode = 3
	}

	fmt.Printf("%s %s\n", prefix[errorCode], messages)
	os.Exit(errorCode)
}
