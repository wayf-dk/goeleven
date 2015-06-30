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
	"strings"
	"sync"
	"time"
)

type Hsm struct {
	session pkcs11.SessionHandle
	used    int
	started time.Time
	sessno  int
}

type aclmap struct {
	handle       pkcs11.ObjectHandle
	sharedsecret string
	label        string
}

var currentsessions int
var hsm1 Hsm
var sem chan Hsm
var pguard sync.Mutex
var p *pkcs11.Ctx
var config = map[string]string{
	"GOELEVEN_HSMLIB":        "",
	"GOELEVEN_INTERFACE":     "localhost:8080",
	"GOELEVEN_ALLOWEDIP":     "127.0.0.1",
	"GOELEVEN_SLOT":          "",
	"GOELEVEN_SLOT_PASSWORD": "",
	"GOELEVEN_KEY_LABEL":     "",
	"GOELEVEN_MINSESSIONS":   "1",
	"GOELEVEN_MAXSESSIONS":   "1",
	"GOELEVEN_MAXSESSIONAGE": "1000000",
	"GOELEVEN_MECH":          "CKM_RSA_PKCS",
	"GOELEVEN_DEBUG":         "false",
	"SOFTHSM_CONF":           "softhsm.conf",
	"GOELEVEN_HTTPS_KEY":     "false",
	"GOELEVEN_HTTPS_CERT":    "false",
}

var keymap map[string]aclmap

var sharedsecretlen = map[string]int{
	"min": 12,
	"max": 32,
}

func main() {
	currentsessions = 0
	keymap = make(map[string]aclmap)
	//wd, _ := os.Getwd()
	initConfig()
	p = pkcs11.New(config["GOELEVEN_HSMLIB"])
	p.Initialize()
	handlesessions()
	http.HandleFunc("/", handler)
	var err error
	if config["GOELEVEN_HTTPS_CERT"] == "false" {
		err = http.ListenAndServe(config["GOELEVEN_INTERFACE"], nil)
	} else {
		err = http.ListenAndServeTLS(config["GOELEVEN_INTERFACE"], config["GOELEVEN_HTTPS_CERT"], config["GOELEVEN_HTTPS_KEY"], nil)
	}
	if err != nil {
		fmt.Printf("main(): %s\n", err)
	}
}

// initConfig read several Environment variables and based on them initialise the configuration
func initConfig() {
	envFiles := []string{"GOELEVEN_HSMLIB"}

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

	s := <-sem

	keys := strings.Split(config["GOELEVEN_KEY_LABEL"], ",")

	for _, v := range keys {

		parts := strings.Split(v, ":")
		label := parts[0]
		sharedsecret := parts[1]
        // Test validity of key specific sharedsecret
        if len(sharedsecret) < sharedsecretlen["min"] || len(sharedsecret) > sharedsecretlen["max"] {
            exit(fmt.Sprintf("problem with sharedsecret: '%s' for label: '%s'", sharedsecret, label), 2)
        }

		template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
		if e := p.FindObjectsInit(s.session, template); e != nil {
			panic(fmt.Sprintf("Failed to init: %s\n", e.Error()))
		}
		obj, b, e := p.FindObjects(s.session, 2)

		debug(fmt.Sprintf("Obj %v\n", obj))
		if e != nil {
			exit(fmt.Sprintf("Failed to find: %s %v\n", e.Error(), b), 2)
		}
		if e := p.FindObjectsFinal(s.session); e != nil {
			exit(fmt.Sprintf("Failed to finalize: %s\n", e.Error()), 2)
		}
		debug(fmt.Sprintf("found keys: %v\n", len(obj)))
		if len(obj) == 0 {
			exit(fmt.Sprintf("did not find a key with label '%s'", label), 2)
		}
		keymap[label] = aclmap{obj[0], sharedsecret, label}
	}

	fmt.Printf("hsm initialized new: %#v\n", keymap)

	sem <- s

	debug(fmt.Sprintf("sem: %v\n", len(sem)))
}

// Client authenticate/authorization
func authClient(sharedkey string, slot string, keylabel string, mech string) error {
	//  Check sharedkey
	//  Check slot nummer
	if slot != config["GOELEVEN_SLOT"] {
		return errors.New("Slot number does not match")
	}
	//  Check key aliases/label
	if _, present := keymap[keylabel]; !present {
		return errors.New(fmt.Sprintf("Key label does not match %s", keylabel))
	}

	if sharedkey != keymap[keylabel].sharedsecret {
		return errors.New(fmt.Sprintf("Client secret for label: '%s' does not match", keymap[keylabel].label))
	}

	//  Check key mech
	if mech != config["GOELEVEN_MECH"] {
		return errors.New("Mech does not match")
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

	fmt.Println("access attempt from:", r.RemoteAddr)
	ips := strings.Split(config["GOELEVEN_ALLOWEDIP"], ",")
	ip := strings.Split(r.RemoteAddr, ":")
	var allowed bool
	for _, v := range ips {
		allowed = allowed || ip[0] == v
	}

	if !allowed {
		fmt.Println("unauthorised access attempt from:", r.RemoteAddr)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var err error
	var validPath = regexp.MustCompile("^/(\\d+)/([a-zA-Z0-9\\.]+)/sign$")
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
	err = authClient(b["sharedkey"].(string), mSlot, mKeyAlias, b["mech"].(string))
	if err != nil {
		http.Error(w, "Invalid input", 500)
		fmt.Printf("authClient: %v\n", err.Error())
		return
	}

	sig, err, sessno := signing(data, keymap[mKeyAlias].handle)
	if err != nil {
		http.Error(w, "Invalid output", 500)
		fmt.Printf("signing: %v %v\n", err.Error(), sessno)
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

	fmt.Printf("slot: %v\n", slot)
	session, e := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION)

	if e != nil {
		panic(fmt.Sprintf("Failed to open session: %s\n", e.Error()))
	}

	p.Login(session, pkcs11.CKU_USER, config["GOELEVEN_SLOT_PASSWORD"])

	return Hsm{session, 0, time.Now(), sessno}
}

// TODO: Cleanup
// TODO: Documentation
func signing(data []byte, key pkcs11.ObjectHandle) ([]byte, error, int) {
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
	fmt.Printf("hsm: %v %v\n", s, key)
	//p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, key)
	p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, key)
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
