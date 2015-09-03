package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/facebookgo/grace/gracehttp"
	"github.com/wayf-dk/pkcs11"
	"io/ioutil"
	"log"
	//	"log/syslog"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Hsm struct {
	session pkcs11.SessionHandle
}

type aclmap struct {
	handle       pkcs11.ObjectHandle
	sharedsecret string
	label        string
}

var (
	contextmutex sync.RWMutex
	context      = make(map[*http.Request]map[string]string)

	maxsessions   int
	p             *pkcs11.Ctx
	sem           chan Hsm
	pkcs11liblock chan int

	config = map[string]string{
		"GOELEVEN_HSMLIB":        "",
		"GOELEVEN_INTERFACE":     "localhost:8080",
		"GOELEVEN_ALLOWEDIP":     "127.0.0.1",
		"GOELEVEN_SLOT":          "",
		"GOELEVEN_SLOT_PASSWORD": "",
		"GOELEVEN_KEY_LABEL":     "",
		"GOELEVEN_MAXSESSIONS":   "1",
		"GOELEVEN_MECH":          "CKM_RSA_PKCS",
		"SOFTHSM_CONF":           "softhsm.conf",
		"GOELEVEN_HTTPS_KEY":     "false",
		"GOELEVEN_HTTPS_CERT":    "false",
	}

	keymap map[string]aclmap

	sharedsecretlen = map[string]int{
		"min": 12,
		"max": 32,
	}

    src = rand.NewSource(time.Now().UnixNano())
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

func main() {
	//	logwriter, e := syslog.New(syslog.LOG_NOTICE, "goeleven")
	//	if e == nil {
	//		log.SetOutput(logwriter)
	//	}

	keymap = make(map[string]aclmap)
	initConfig()

	pkcs11liblock = make(chan int, 1)
	pkcs11liblock <- 1
	p = pkcs11.New(config["GOELEVEN_HSMLIB"])

	go bginit()

	http.HandleFunc("/status", statushandler)
	http.HandleFunc("/", handler)
	var err error
	if config["GOELEVEN_HTTPS_CERT"] == "false" {
		gracehttp.Serve(
			&http.Server{Addr: config["GOELEVEN_INTERFACE"], Handler: Log(http.DefaultServeMux)})
	} else {
		err = http.ListenAndServeTLS(config["GOELEVEN_INTERFACE"], config["GOELEVEN_HTTPS_CERT"], config["GOELEVEN_HTTPS_KEY"], nil)
	}
	if err != nil {
		log.Printf("main(): %s\n", err)
	}
	log.Printf("after ListenAndServer\n")
}

func bginit() {
	// Init channel
tryagain:
	for {
		if err := prepareobjects(config["GOELEVEN_KEY_LABEL"]); err != nil {
			log.Printf("Waiting for HSM\n")
			time.Sleep(5 * time.Second)
			continue tryagain
		}
		break
	}
	go initpkcs11lib(false)
}

func Log(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contextmutex.Lock()
		ctx := make(map[string]string)
		context[r] = ctx
		contextmutex.Unlock()
		starttime := time.Now()
		handler.ServeHTTP(w, r)

		status := 200
		if ctx["err"] != "" {
			status = 500
		}
		log.Printf("%s %s %s %1.3f %d/%d %d %s", r.RemoteAddr, r.Method, r.URL, time.Since(starttime).Seconds(), len(sem), cap(sem), status, ctx["err"])

		contextmutex.Lock()
		delete(context, r)
		contextmutex.Unlock()
	})
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
	for k, v := range config {
		// Don't write PASSWORD to debug
		if k == "GOELEVEN_SLOT_PASSWORD" {
			v = "xxx"
		}
		log.Printf("%v: %v\n", k, v)
	}

	// Check file exists
	for _, v := range envFiles {
		_, err := os.Stat(config[v])
		if err != nil {
			log.Panicf("%s %s", v, err.Error())
		}
	}
	max, _ := strconv.ParseInt(config["GOELEVEN_MAXSESSIONS"], 10, 0)
	maxsessions = int(max)
}

// Prepareobjects returns a map of the label to object id for the given labels.
// Returns an error if something goes wrong - the caller is supposed to keep trying
// until no error is returned
func prepareobjects(labels string) (err error) {
	// String->int64->int convert
	var s Hsm
	err = p.Initialize()
	defer p.Finalize()
	s, err = initsession()
	if err != nil {
		return
	}
	defer p.CloseSession(s.session)
	defer p.Logout(s.session)

	log.Printf("initsession result: %v\n", err)

	keys := strings.Split(labels, ",")

	for _, v := range keys {

		parts := strings.Split(v, ":")
		label := parts[0]
		sharedsecret := parts[1]
		// Test validity of key specific sharedsecret
		if len(sharedsecret) < sharedsecretlen["min"] || len(sharedsecret) > sharedsecretlen["max"] {
			log.Panicf("problem with sharedsecret: '%s' for label: '%s'", sharedsecret, label)
		}

		template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
		if err = p.FindObjectsInit(s.session, template); err != nil {
			//syscall.Kill(syscall.Getpid(), syscall.SIGUSR2)
			//panic(fmt.Sprintf("%d Failed to init: %s\n", syscall.Getpid(), e.Error()))
			return errors.New("")
		}
		obj, b, e := p.FindObjects(s.session, 2)

		log.Printf("Obj %v\n", obj)
		if e != nil {
			log.Fatalf("Failed to find: %s %v\n", e.Error(), b)
		}
		if e := p.FindObjectsFinal(s.session); e != nil {
			log.Fatalf("Failed to finalize: %s\n", e.Error())
		}
		log.Printf("found keys: %v\n", len(obj))
		if len(obj) == 0 {
			log.Fatalf("did not find a key with label '%s'", label)
		}
		keymap[label] = aclmap{obj[0], sharedsecret, label}
	}

	log.Printf("hsm initialized new: %#v\n", keymap)
	return
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

// Utility to get correct error in log, while just sending generic 500 to client
func logandsenderror(w http.ResponseWriter, err string, context map[string]string) {
	context["err"] = err
	http.Error(w, "Invalid Input", 500)
}

// TODO: Cleanup
// TODO: Documentation
// TODO: Error handling
/*
 * If error then send HTTP 500 to client and keep the server running
 *
 */
func handler(w http.ResponseWriter, r *http.Request) {

	defer r.Body.Close()
	contextmutex.RLock()
	ctx := context[r]
	contextmutex.RUnlock()

	ips := strings.Split(config["GOELEVEN_ALLOWEDIP"], ",")
	ip := strings.Split(r.RemoteAddr, ":")
	var allowed bool
	for _, v := range ips {
		allowed = allowed || ip[0] == v
	}

	if !allowed {
		logandsenderror(w, "Unauthorised access attempt", ctx)
		return
	}

	// handle non ok urls gracefully
	var err error
	var validPath = regexp.MustCompile("^/(\\d+)/([a-zA-Z0-9\\.]+)/sign$")
	match := validPath.FindStringSubmatch(r.URL.Path)
	if match == nil {
		logandsenderror(w, "Invalid path", ctx)
		return
	}
	mSlot := match[1]
	mKeyAlias := match[2]

	body, _ := ioutil.ReadAll(r.Body)

	// Parse JSON
	var b struct {
		Data      string `json:"data"`
		Mech      string `json:"mech"`
		Sharedkey string `json:"sharedkey"`
	}
	err = json.Unmarshal(body, &b)
	if err != nil {
		logandsenderror(w, fmt.Sprintf("json.unmarshall: %v", err.Error()), ctx)
		return
	}

	data, err := base64.StdEncoding.DecodeString(b.Data)
	if err != nil {
		logandsenderror(w, fmt.Sprintf("DecodeString: %v", err.Error()), ctx)
		return
	}

	if len(data) == 0 {
		logandsenderror(w, "empty payload", ctx)
		return
	}

	// Client auth
	err = authClient(b.Sharedkey, mSlot, mKeyAlias, b.Mech)
	if err != nil {
		logandsenderror(w, fmt.Sprintf("authClient: %v", err.Error()), ctx)
		return
	}

	sig, err := signing(data, mKeyAlias)
	if err != nil {
		logandsenderror(w, fmt.Sprintf("signing error: %s", err.Error()), ctx)
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
		logandsenderror(w, fmt.Sprintf("json.marshall: %s", err.Error()), ctx)
		return
	}

	fmt.Fprintf(w, "%s\n\n", json)
	r.Body.Close()
}

func statushandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	contextmutex.RLock()
	ctx := context[r]
	contextmutex.RUnlock()

    // signing expects a hash prefixed with the DER encoded oid for the hashfunction - this is for sha256
    data :=  []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
    data = append(data,  RandStringBytesMaskImprSrc(40) ...)
	_, err := signing(data, "wildcard.test.lan.key")
	if err != nil {
		logandsenderror(w, fmt.Sprintf("signing error: %s", err.Error()), ctx)
		return
	}
}

// Make a random string - from http://stackoverflow.com/a/31832326
func RandStringBytesMaskImprSrc(n int) []byte {
    b := make([]byte, n)
    // A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
    for i, cache, remain := n-1, src.Int63(), letterIdxMax; i >= 0; {
        if remain == 0 {
            cache, remain = src.Int63(), letterIdxMax
        }
        if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
            b[i] = letterBytes[idx]
            i--
        }
        cache >>= letterIdxBits
        remain--
    }

    return b
}

func initpkcs11lib(restart bool) {
	select {
	case _ = <-pkcs11liblock:
		log.Printf("initpkcs11lib restart %v\n", restart)
		// send a SIGUSR2 signal - once - to self - to let grace start a new process for serving new requests
		// we just fails ungracefully when a new process tells us to get lost ...
		if restart {
			syscall.Kill(syscall.Getpid(), syscall.SIGUSR2)
			return
		}
	default:
		return
	}

	sem = make(chan Hsm, maxsessions)

	err := p.Initialize()
	for err != nil {
		if err.Error() == "pkcs11: 0x191: CKR_CRYPTOKI_ALREADY_INITIALIZED" {
			err = nil
		} else {
			log.Printf("waiting: %v\n", err.Error())
			time.Sleep(1 * time.Second)
			err = p.Initialize()
		}
	}

	for currentsessions := 0; currentsessions < maxsessions; currentsessions++ {
		s, _ := initsession()
		sem <- s
	}

	pkcs11liblock <- 1
	log.Printf("initialized lib\n")
}

// TODO: Cleanup
// TODO: Documentation
func initsession() (Hsm, error) {
	slot, _ := strconv.ParseUint(config["GOELEVEN_SLOT"], 10, 32)

	log.Printf("slot: %v\n", slot)
	session, e := p.OpenSession(uint(slot), pkcs11.CKF_SERIAL_SESSION)

	if e != nil {
		log.Printf("Failed to open session: %s\n", e.Error())
		// panic(log.Sprintf("Failed to open session: %s\n", e.Error()))
	}

	e = p.Login(session, pkcs11.CKU_USER, config["GOELEVEN_SLOT_PASSWORD"])

	if e != nil {
		log.Printf("Failed to login to session: %s\n", e.Error())
		// panic(log.Sprintf("Failed to open session: %s\n", e.Error()))
	}

	return Hsm{session}, e
}

// TODO: Cleanup
// TODO: Documentation
func signing(data []byte, key string) ([]byte, error) {
	var err error
	s := <-sem

	p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, keymap[key].handle)
	sig, err := p.Sign(s.session, data)
	// to do - do not balk on signing error: pkcs11: 0x21: CKR_DATA_LEN_RANGE
	// or only on signing error: pkcs11: 0x30: CKR_DEVICE_ERROR
	if err != nil {
		go initpkcs11lib(true)
	}

	sem <- s
	return sig, err
}
