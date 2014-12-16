package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"github.com/wayf-dk/pkcs11"
	"regexp"
	"sync"
	"time"
)

type Hsm struct {
	session pkcs11.SessionHandle
	obj     pkcs11.ObjectHandle
	used    int
	started time.Time
}

const (
	minsessions   = 1
	maxsessions   = 1
	maxsessionage = 1000000
)

var currentsessions int
var hsm1 Hsm
var sem chan Hsm
var pguard sync.Mutex
var p *pkcs11.Ctx
var config = map[string]string{
	"GOELEVEN_HSMLIB":        "",
	"GOELEVEN_PORT":          "",
	"GOELEVEN_INTERFACE":     "localhost",
	"GOELEVEN_SLOT":          "",
	"GOELEVEN_SLOT_PASSWORD": "",
	"GOELEVEN_KEY_LABEL":     "",
	"SOFTHSM_CONF":           "softhsm.conf",
}
var flagDebug = true

func main() {
	currentsessions = 0
	//wd, _ := os.Getwd()
	initConfig()
	p = pkcs11.New(config["GOELEVEN_HSMLIB"])
	p.Initialize()
	go handlesessions()
	http.HandleFunc("/", handler)
	http.ListenAndServe(config["GOELEVEN_INTERFACE"]+":"+config["GOELEVEN_PORT"], nil)
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
	sem = make(chan Hsm, maxsessions)
	for currentsessions < maxsessions {
		currentsessions++
		sem <- inithsm()
	}
	debug(fmt.Sprintf("sem: %v\n", len(sem)))
}

func handler(w http.ResponseWriter, r *http.Request) {
	var validPath = regexp.MustCompile("^/(\\d+)/([a-zA-Z0-9]+)/sign$")
	m := validPath.FindStringSubmatch(r.URL.Path)
	//    xauth := ""

	if xauthheader := r.Header["X-Auth"]; xauthheader != nil {
		//        xauth = xauthheader[0]
	}
	//fmt.Printf("headers: %v\n", xauth)
	defer r.Body.Close()
	body, _ := ioutil.ReadAll(r.Body)
	//var b struct { Data,Mech string }
	var b map[string]interface{}
	_ = json.Unmarshal(body, &b)
	debug(fmt.Sprintf("json: %v\n", b))
	data, _ := base64.StdEncoding.DecodeString(b["data"].(string))
	//fmt.Printf("json: %s %v\n", data, err)
	sig, _ := xxx(data)
	sigs := base64.StdEncoding.EncodeToString(sig)
	type Res struct{ Slot, Mech, Signed string }
	res := Res{m[1], "mech", sigs}
	json, _ := json.Marshal(res)
	//fmt.Printf("body: %v %v\n", b, err)
	fmt.Fprintf(w, "%s\n\n", json)

}

func inithsm() Hsm {
	pguard.Lock()
	defer pguard.Unlock()
	slots, _ := p.GetSlotList(true)
	debug(fmt.Sprintf("slots: %v\n", slots))
	session, _ := p.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKR_SESSION_READ_ONLY)
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

	return Hsm{session, obj[0], 0, time.Now()}
}

func xxx(data []byte) ([]byte, error) {
	s := <-sem
	s.used++
	if s.used > 10000 || time.Now().Sub(s.started) > 1000*time.Second {
		p.Logout(s.session)
		p.CloseSession(s.session)
		//p.Finalize()
		//p.Destroy()
		s = inithsm()
	}
	fmt.Printf("hsm: %v\n", s)
	//    p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, s.obj)
	p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, s.obj)
	sig, err := p.Sign(s.session, data)
	fmt.Printf("err: %v\n", err)

	sem <- s
	return sig, nil
}

// Utils

func debug(messages string) {
	if flagDebug {
		fmt.Print(messages)
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
