package goeleven

/*
    /(sign|encrypt|decrypt)/<slot label>/<key label/
    Post data:
		Data      string `json:"data"`
		Mech      string `json:"mech"`   // using pkscs11 names: signing: CKM_SHA1_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_RSA_PKCS(prehashed) decrypting: CKM_RSA_PKCS_OAEP
		Digest    string `json:"digest"  // using pkcs11 names: CKM_SHA_1, CKM_SHA256 - only used for decrypting
		Function  string `json:"Function" // decrypt | sign
		Sharedkey string `json:"sharedkey"`
*/

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unsafe"

	"github.com/miekg/pkcs11"
	"x.config"
)

type (
	Hsm struct {
		session pkcs11.SessionHandle
	}

	aclmap struct {
		handle       pkcs11.ObjectHandle
		sharedsecret string
		label        string
	}

	Request struct {
		Data      string `json:"data"`
		Mech      string `json:"mech"`
		Digest    string `json:"digest"`
		Function  string `json:"function"`
		Sharedkey string `json:"sharedkey"`
	}

	appHandler func(http.ResponseWriter, *http.Request) error
)

var (
	p    *pkcs11.Ctx
	sem  chan Hsm
	slot uint

	methods = map[string]uint{
		"CKM_SHA1_RSA_PKCS":   pkcs11.CKM_SHA1_RSA_PKCS,
		"CKM_SHA256_RSA_PKCS": pkcs11.CKM_SHA256_RSA_PKCS,
		"CKM_RSA_PKCS":        pkcs11.CKM_RSA_PKCS,
		"CKM_RSA_PKCS_OAEP":   pkcs11.CKM_RSA_PKCS_OAEP,
		"CKM_SHA_1":           pkcs11.CKM_SHA_1,
		"CKM_SHA256":          pkcs11.CKM_SHA256,
	}

	keymap map[string]aclmap

	slotmap map[string]pkcs11.ObjectHandle

	operations = map[string]func([]byte, Request, pkcs11.ObjectHandle) ([]byte, error){
		"sign":    Sign,
		"decrypt": Decrypt,
		"encrypt": Encrypt,
	}

	sharedsecretlen = map[string]int{
		"min": 12,
		"max": 32,
	}

	src = rand.NewSource(time.Now().UnixNano())

	fatalerrors = map[uint]bool{
		pkcs11.CKR_DEVICE_ERROR:       true,
		pkcs11.CKR_KEY_HANDLE_INVALID: true,
	}

	conf config.GoElevenConfig
)

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits

	crypto_officer = pkcs11.CKU_USER // safenet crypto_officer maps to CKU.USER !!!
	crypto_user    = 0x80000001      // safenet extension
)

func Init(c config.GoElevenConfig) {
	if c.SlotPassword == "" {
		return
	}
	conf = c
	keymap = make(map[string]aclmap)
	slotmap = make(map[string]pkcs11.ObjectHandle)

	p = pkcs11.New(conf.HsmLib)
    if p == nil {
    	log.Fatal("No cryptoki lib available")
    }

	// sem must not be nil as this will block forever all clients that tries to read before
	// clients are made available in sem asynchronously as they become ready in initpkcs11lib
	sem = make(chan Hsm, conf.MaxSessions)

	bginit()

	if conf.Intf != "" {
		http.Handle("/status", appHandler(statushandler))
		http.Handle("/", appHandler(handler))

		err := http.ListenAndServe(conf.Intf, http.DefaultServeMux)

		if err != nil {
			log.Printf("main(): %s\n", err)
		}
		log.Printf("after ListenAndServer\n")
	}
}

func bginit() {
tryagain:
	for {
		if err := prepareobjects(conf.KeyLabels); err != nil {
			log.Printf("Waiting for HSM\n")
			time.Sleep(5 * time.Second)
			continue tryagain
		}
		break
	}
	log.Printf("initpkcs11lib")
	go initpkcs11lib()
}

// Prepareobjects returns a map of the label to object id for the given labels.
// Returns an error if something goes wrong - the caller is supposed to keep trying
// until no error is returned
func prepareobjects(labels string) (err error) {
	// String->int64->int convert
	var s Hsm
	err = p.Initialize()
	//defer p.Finalize()

	slots, e := p.GetSlotList(true)
	if e != nil {
		log.Fatalf("slots %s\n", e.Error())
	}

	for _, s := range slots {
		tokeninfo, _ := p.GetTokenInfo(s)
		if tokeninfo.Label == conf.Slot { // tokeninfo.SerialNumber is string
			slot = s
			log.Printf("slot: %d %s\n", slot, tokeninfo.Label)
			break
		}
	}

	s, err = initsession()
	if err != nil {
		return
	}
	//defer p.CloseSession(s.session)
	//defer p.Logout(s.session)

	keys := strings.Split(labels, ",")

	keylabels := []string{}
	for _, v := range keys {

		parts := strings.Split(v, ":")
		label := parts[0]
		keylabels = append(keylabels, label)
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

		if e != nil {
			log.Fatalf("Failed to find: %s %v\n", e.Error(), b)
		}
		if e := p.FindObjectsFinal(s.session); e != nil {
			log.Fatalf("Failed to finalize: %s\n", e.Error())
		}
		if len(obj) != 1 {
			log.Fatalf("did not find one (and only one) key with label '%s'", label)
		}
		log.Printf("found key: %d %s\n", obj[0], label)
		keymap[label] = aclmap{obj[0], sharedsecret, label}
	}

	return
}

// Client authenticate/authorization
func authClient(sharedkey string, slot string, keylabel string, mech string) error {
	//  Check sharedkey
	//  Check slot nummer
	if slot != conf.Slot {
		return errors.New("Slot number does not match")
	}
	//  Check key aliases/label
	if _, present := keymap[keylabel]; !present {
		return errors.New(fmt.Sprintf("Key label does not match %s", keylabel))
	}

	if sharedkey != keymap[keylabel].sharedsecret {
		return errors.New(fmt.Sprintf("Client secret for label: '%s' does not match", keymap[keylabel].label))
	}

	// client ok
	return nil
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	starttime := time.Now()
	err := fn(w, r)
	status := 200
	if err != nil {
		status = 500
	} else {
		err = fmt.Errorf("OK")
	}
	log.Printf("%s %s %s %1.3f %d/%d %d %s", r.RemoteAddr, r.Method, r.URL, time.Since(starttime).Seconds(), len(sem), cap(sem), status, err)
}

/*
 * If error then send HTTP 500 to client and keep the server running
 *
 */
func handler(w http.ResponseWriter, r *http.Request) (err error) {

	defer r.Body.Close()

	ips := strings.Split(conf.AllowedIP, ",")
	ip := strings.Split(r.RemoteAddr, ":")
	var allowed bool
	for _, v := range ips {
		allowed = allowed || ip[0] == v
	}

	if !allowed {
		return fmt.Errorf("Unauthorised access attempt")
	}

	// handle non ok urls gracefully
	var validPath = regexp.MustCompile("^/([a-zA-Z0-9\\.]+)/([-a-zA-Z0-9\\.]+)$")
	//log.Printf("url: %v\n", r.URL.Path)
	match := validPath.FindStringSubmatch(r.URL.Path)
	if match == nil {
		return fmt.Errorf("Invalid path")
	}

	mSlotAlias := match[1]
	mKeyAlias := match[2]

	body, _ := ioutil.ReadAll(r.Body)

	b := Request{}

	err = json.Unmarshal(body, &b)
	if err != nil {
		return
	}
	//log.Printf("req: %v\n", b)

	data, err := base64.StdEncoding.DecodeString(b.Data)

	if err != nil {
		return
	}

	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}

	// Client auth
	err = authClient(b.Sharedkey, mSlotAlias, mKeyAlias, b.Mech)
	if err != nil {
		return
	}

	key := keymap[mKeyAlias].handle

	sig, err := operations[b.Function]([]byte(data), b, key)
	if err != nil {
		return
	}

	result := base64.StdEncoding.EncodeToString(sig)

	type Res struct {
		Result string `json:"signed"`
	}
	res := Res{result}
	json, err := json.Marshal(res)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "%s\n\n", json)
	r.Body.Close()
	return
}

func statushandler(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	err = HSMStatus()
	return
}

func HSMStatus() (err error) {
	// signing expects a hash prefixed with the DER encoded oid for the hashfunction - this is for sha256
	data := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}
	data = append(data, RandStringBytesMaskImprSrc(40)...)
	b := Request{Mech: "CKM_RSA_PKCS"}

	for _, key := range keymap { // just use one of the keys
		_, err = Sign(data, b, key.handle)
		break
	}
	return
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

func initpkcs11lib() {
	/*
		err := p.Initialize()
		for err != nil {
			log.Fatal("Failed to initialize pkcs11")
		}
	*/

	for currentsessions := 0; currentsessions < conf.MaxSessions; currentsessions++ {
		s, _ := initsession()
		// need to call FindObjectsInit to be able to use objects in ha partition
		template := []*pkcs11.Attribute{}
		_ = p.FindObjectsInit(s.session, template)
		sem <- s
	}

	log.Printf("initialized goeleven %d sessions\n", conf.MaxSessions)
}

// TODO: Cleanup
// TODO: Documentation
func initsession() (Hsm, error) {

	session, e := p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)

	if e != nil {
		log.Fatalf("Failed to open session: %s\n", e.Error())
	}

	e = p.Login(session, crypto_user, conf.SlotPassword)
//	e = p.Login(session, crypto_officer, conf.SlotPassword)

	if e != nil {
		log.Printf("Failed to login to session: %s\n", e.Error())
		// panic(log.Sprintf("Failed to open session: %s\n", e.Error()))
	}

	return Hsm{session}, e
}

func Dispatch(req string, params Request) (res []byte, err error) {
	u, err := url.Parse(req)
	if err != nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(params.Data)
	if err != nil {
		return
	}
	key := keymap[strings.Split(u.Path, "/")[2]].handle
	res, err = operations[params.Function](data, params, key)
	return
}

// TODO: Cleanup
// TODO: Documentation
func Sign(data []byte, parms Request, key pkcs11.ObjectHandle) ([]byte, error) {
	var err error
	s := <-sem
	defer func() { sem <- s }()

	err = p.SignInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], nil)}, key)
	handlefatalerror(err)
	sig, err := p.Sign(s.session, data)
	handlefatalerror(err)

	return sig, err
}

func Encrypt(data []byte, parms Request, key pkcs11.ObjectHandle) ([]byte, error) {

	type oaepParams struct {
		hashAlg         uint
		mgf             uint
		source          uint
		pSourceData     *byte
		ulSourceDataLen uint
	}

	buf := make([]byte, int(unsafe.Sizeof(oaepParams{})))
	params := (*oaepParams)(unsafe.Pointer(&buf[0]))

	params.hashAlg = methods[parms.Digest]
	params.mgf = 1    // CKG_MGF1_SHA1
	params.source = 1 // CKZ_DATA_SPECIFIED
	params.pSourceData = nil
	params.ulSourceDataLen = 0

	var err error
	s := <-sem
	defer func() { sem <- s }()

	err = p.EncryptInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], buf)}, key)
	handlefatalerror(err)
	plain, err := p.Encrypt(s.session, data)
	handlefatalerror(err)

	return plain, err
}

// TODO: Cleanup
// TODO: Documentation

func Decrypt(data []byte, parms Request, key pkcs11.ObjectHandle) ([]byte, error) {

	type oaepParams struct {
		hashAlg         uint
		mgf             uint
		source          uint
		pSourceData     *byte
		ulSourceDataLen uint
	}

	buf := make([]byte, int(unsafe.Sizeof(oaepParams{})))
	params := (*oaepParams)(unsafe.Pointer(&buf[0]))

	params.hashAlg = methods[parms.Digest]
	params.mgf = 1    // CKG_MGF1_SHA1
	params.source = 1 // CKZ_DATA_SPECIFIED
	params.pSourceData = nil
	params.ulSourceDataLen = 0

	var err error
	s := <-sem
	defer func() { sem <- s }()

	err = p.DecryptInit(s.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], buf)}, key)
	handlefatalerror(err)
	plain, err := p.Decrypt(s.session, data)
	handlefatalerror(err)
	return plain, err
}

func handlefatalerror(err error) {
	if err != nil && fatalerrors[uint(err.(pkcs11.Error))] {
		log.Fatalf("goeleven FATAL error: %s\n", err.Error())
	}
}
