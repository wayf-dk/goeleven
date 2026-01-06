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
	"strings"
	"time"
	"unsafe"

	"github.com/miekg/pkcs11"
	"x.config"
)

type (
	keyInfo struct {
		handle                    pkcs11.ObjectHandle
		sharedsecret, label, slot string
	}

	testslot struct {
		label, site string
		session     pkcs11.SessionHandle
		handle      pkcs11.ObjectHandle
		channel     chan bool
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
	p             *pkcs11.Ctx
	sessions      = map[string]chan pkcs11.SessionHandle{}
	keys          = map[string]keyInfo{}
	slots         = map[string]uint{}
	testslots     = []testslot{}
	HSMStatusData []byte
	haSlot        string
	testkey       string
	allowedIP     []string

	methods = map[string]uint{
		"CKM_SHA1_RSA_PKCS":   pkcs11.CKM_SHA1_RSA_PKCS,
		"CKM_SHA256_RSA_PKCS": pkcs11.CKM_SHA256_RSA_PKCS,
		"CKM_RSA_PKCS":        pkcs11.CKM_RSA_PKCS,
		"CKM_RSA_PKCS_OAEP":   pkcs11.CKM_RSA_PKCS_OAEP,
		"CKM_SHA_1":           pkcs11.CKM_SHA_1,
		"CKM_SHA256":          pkcs11.CKM_SHA256,
		"CKM_RSA_X_509":       pkcs11.CKM_RSA_X_509,
		"CKM_EDDSA":           0x80000c03,
	}

	operations = map[string]func([]byte, Request, keyInfo) ([]byte, error){
		"sign":    Sign,
		"decrypt": Decrypt,
		"encrypt": Encrypt,
	}

	fatalerrors = map[uint]bool{
		pkcs11.CKR_DEVICE_ERROR:       true,
		pkcs11.CKR_KEY_HANDLE_INVALID: true,
	}
)

const (
	crypto_officer = pkcs11.CKU_USER // safenet crypto_officer maps to CKU.USER !!!
	crypto_user    = 0x80000001      // safenet extension
)

func Init(conf config.GoElevenConfig) {
	if conf.SlotPassword == "" {
		return
	}

	log.SetFlags(0) // no predefined time
	testkey = conf.Testkey
	allowedIP = strings.Split(conf.AllowedIP, ",")

	const digestMethod = "sha512"
	buf := make([]byte, config.CryptoMethods[digestMethod].Hash.Size())
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}

	HSMStatusData = append([]byte(config.CryptoMethods[digestMethod].DerPrefix), buf...)

	p = pkcs11.New(conf.HsmLib)
	if p == nil {
		log.Fatal("No cryptoki lib available")
	}

	err = p.Initialize()
	if err != nil {
		log.Fatal(err)
	}

	// sem must not be nil as this will block forever all clients that tries to read before
	// clients are made available in sem asynchronously as they become ready in initpkcs11lib
	for label, slot := range conf.Slots {
		sessions[label] = make(chan pkcs11.SessionHandle, slot.Sessions)
	}

	for label, slot := range conf.Slots { // here we need to be able to handle all slots
		switch slot.Site {
		case "ha":
			haSlot = label
		}
		testslots = append(testslots, testslot{label, slot.Site, pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_OBJECT_HANDLE_INVALID, make(chan bool)})
	}

	if err := prepareobjects(conf); err != nil { // prepare for use of ha slot only
		log.Fatal(err)
	}

	go func() {
		for s := uint(0); s < conf.Slots[haSlot].Sessions; s++ {
			sess, _ := initsession(slots[haSlot], conf.SlotPassword)
			sessions[haSlot] <- sess
		}
		log.Printf("initialized goeleven slot: %s %d sessions\n", haSlot, conf.Slots[haSlot].Sessions)
	}()

	//HSMStatus()

	ticker := time.NewTicker(5 * time.Second)
	go func() {
		for {
			<-ticker.C
			HSMStatus2()
		}
	}()

	for _, slot := range testslots {
		go handleTestslot(slot, conf)
	}

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

// Prepareobjects returns a map of the label to object id for the given labels.
// Returns an error if something goes wrong - the caller is supposed to keep trying
// until no error is returned
func prepareobjects(conf config.GoElevenConfig) (err error) {
	// Sessions for initializing key handles, not the global channels of sessions
	// The key handles are also valid for the sessions created in createSessions
	sessions := map[string]pkcs11.SessionHandle{}

	slotlist, e := p.GetSlotList(true)
	if e != nil {
		log.Fatalf("slots %s\n", e.Error())
	}

	for _, slot := range slotlist {
		tokeninfo, _ := p.GetTokenInfo(slot)
		if tokeninfo.Label == haSlot {
            session, err := initsession(slot, conf.SlotPassword)
            if err != nil {
                return err
            }
			slots[tokeninfo.Label] = slot
			sessions[tokeninfo.Label] = session
			log.Printf("slot: %d %s %s\n", slot, tokeninfo.Label, tokeninfo.SerialNumber)
		}
	}

	for _, v := range conf.Keys {
		parts := strings.Split(v, ":")
		slotlabel, sharedsecret := parts[0], parts[1]
		parts = strings.Split(slotlabel, "/")
		slot, label := parts[1], parts[2] // slotlabel now starts with a /
		key, err := findPrivatekey(label, sessions[slot])
		if err != nil {
			return err
		}
		log.Printf("found key: %d %s\n", key, slotlabel)
		keys[slotlabel] = keyInfo{key, sharedsecret, slotlabel, slot}
		if keypath := conf.Slots[slot].Keypath; keypath != "" {
			keys[keypath+label] = keys[slotlabel]
			log.Printf("found key: %d %s\n", key, keypath+label)
		}
	}
	return
}

func findPrivatekey(label string, session pkcs11.SessionHandle) (obj pkcs11.ObjectHandle, err error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label), pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY)}
	if err = p.FindObjectsInit(session, template); err != nil {
		return
	}
	objs, b, e := p.FindObjects(session, 2)
	if e != nil {
		err = errors.New(fmt.Sprintf("Failed to find: %s %v\n", e.Error(), b))
		return
	}
	if e := p.FindObjectsFinal(session); e != nil {
		err = errors.New(fmt.Sprintf("Failed to FindObjectsFinal: %s\n", e.Error()))
		return
	}
	if len(objs) != 1 {
		err = errors.New(fmt.Sprintf("did not find one (and only one) key with label '%s'", label))
		return
	}
	return objs[0], err
}

func createSessions(conf config.GoElevenConfig) {
	for label, slot := range conf.Slots {
		for s := uint(0); s < slot.Sessions; s++ {
			sess, _ := initsession(slots[label], conf.SlotPassword)
			sessions[label] <- sess
			log.Println(label, s)
		}
		log.Printf("initialized goeleven slot: %s %d sessions\n", label, slot.Sessions)
	}
}

// TODO: Cleanup
// TODO: Documentation
func initsession(slot uint, password string) (session pkcs11.SessionHandle, err error) {
	session, err = p.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION)

	if err != nil {
		return
	}

	err = p.Login(session, crypto_user, password)
	//	e = p.Login(session, crypto_officer, conf.SlotPassword)

	if err != nil {
		return
	}
	// need to call FindObjectsInit to be able to use objects in ha partition
	p.FindObjectsInit(session, []*pkcs11.Attribute{})
	return
}

func handleTestslot(theslot testslot, conf config.GoElevenConfig) {
	ticker := time.NewTicker(30 * time.Second)
	for {
		if theslot.session == pkcs11.CKR_SESSION_HANDLE_INVALID {
		init:
			for {
			keeptrying:
				for {
					var err error
					slotlist, _ := p.GetSlotList(true)
					for _, slot := range slotlist {
						p.GetSlotInfo(slot) // to re-mount after being off-line
						tokeninfo, e := p.GetTokenInfo(slot)
						if e != nil {
							break keeptrying
						}
						if tokeninfo.SerialNumber == theslot.label || tokeninfo.Label == theslot.label {
							theslot.session, err = initsession(slot, conf.SlotPassword)
							if err != nil {
								break keeptrying
							}
							theslot.handle, err = findPrivatekey(testkey, theslot.session)
							if err == nil {
								break init
							}
						}
					}
					break keeptrying
				}
				<-ticker.C
			}
		}
		err := p.SignInit(theslot.session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil)}, theslot.handle)
		if err == nil {
			_, err = p.Sign(theslot.session, HSMStatusData)
			if err != nil {
    			p.CloseSession(theslot.session)
				theslot.session = pkcs11.CKR_SESSION_HANDLE_INVALID
				continue
			}
		}
		theslot.channel <- true
	}
}

// Client authenticate/authorization
func authClient(sharedkey, key string) error {
	//  Check key aliases/label
	//  Check sharedkey

	if _, present := keys[key]; !present {
		return errors.New(fmt.Sprintf("Key label does not match %s", key))
	}

	if sharedkey != keys[key].sharedsecret {
		return errors.New(fmt.Sprintf("Client secret for label: '%s' does not match", key))
	}

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
	log.Printf("%s %s %s %1.3f %d/%d %d %s", r.RemoteAddr, r.Method, r.URL, time.Since(starttime).Seconds(), 0, 0, status, err)
}

/*
 * If error then send HTTP 500 to client and keep the server running
 *
 */
func handler(w http.ResponseWriter, r *http.Request) (err error) {

	defer r.Body.Close()

	ip := strings.Split(r.RemoteAddr, ":")
	var allowed bool
	for _, v := range allowedIP {
		allowed = allowed || ip[0] == v
	}

	if !allowed {
		return fmt.Errorf("Unauthorised access attempt")
	}

	body, _ := ioutil.ReadAll(r.Body)

	b := Request{}

	err = json.Unmarshal(body, &b)
	if err != nil {
		return
	}

	data, err := base64.StdEncoding.DecodeString(b.Data)
	if err != nil {
		return
	}

	if len(data) == 0 {
		return fmt.Errorf("empty payload")
	}

	// Client auth
	key := r.URL.Path
	err = authClient(b.Sharedkey, key)
	if err != nil {
		return
	}

	sig, err := operations[b.Function]([]byte(data), b, keys[key])
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
	_, err = Sign(HSMStatusData, Request{Mech: "CKM_RSA_PKCS"}, keys["/"+haSlot+"/"+testkey])
	return
}

func HSMStatus2() (err error) {
	const call = " 1234 Call HSMStatus "
	res := map[string]bool{}
	tmpl := map[bool]string{false: ": - ", true: ": OK "}
	tmpl2 := map[bool]string{false: "ERROR:", true: "OK:"}

	for _, slot := range testslots {
		var status bool
		select {
		case status = <-slot.channel:
		default:
		}
		res[slot.site] = status
	}
	ok := true
	msg := ""
	for _, slot := range testslots {
		msg += slot.site + tmpl[res[slot.site]]
		ok = ok && res[slot.site]
	}
	log.Println(tmpl2[ok] + call + msg)
	return
}

func Dispatch(req string, params Request) (res []byte, err error) {
	if p == nil {
		return nil, fmt.Errorf("goeleven not initialized")
	}
	u, err := url.Parse(req)
	if err != nil {
		return
	}
	data, err := base64.StdEncoding.DecodeString(params.Data)
	if err != nil {
		return
	}
	fmt.Println(params, u.Path, keys[u.Path])
	res, err = operations[params.Function](data, params, keys[u.Path])
	return
}

// TODO: Cleanup
// TODO: Documentation
func Sign(data []byte, parms Request, key keyInfo) (sig []byte, err error) {
	session := <-sessions[key.slot]
	defer func() { sessions[key.slot] <- session }()

	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], nil)}, key.handle)
	if err != nil {
		return
	}
	sig, err = p.Sign(session, data)
	if err != nil {
		return
	}
	return
}

func Encrypt(data []byte, parms Request, key keyInfo) (ciphertext []byte, err error) {

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

	session := <-sessions[key.slot]
	defer func() { sessions[key.slot] <- session }()

	err = p.EncryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], buf)}, key.handle)
	handlefatalerror(err)
	ciphertext, err = p.Encrypt(session, data)
	handlefatalerror(err)

	return ciphertext, err
}

// TODO: Cleanup
// TODO: Documentation

func Decrypt(data []byte, parms Request, key keyInfo) (plain []byte, err error) {

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
	params.mgf = map[uint]uint{pkcs11.CKM_SHA_1: pkcs11.CKG_MGF1_SHA1, pkcs11.CKM_SHA256: pkcs11.CKG_MGF1_SHA256}[params.hashAlg]
	params.source = 1 // CKZ_DATA_SPECIFIED
	params.pSourceData = nil
	params.ulSourceDataLen = 0

	session := <-sessions[key.slot]
	defer func() { sessions[key.slot] <- session }()

	err = p.DecryptInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(methods[parms.Mech], buf)}, key.handle)
	handlefatalerror(err)
	plain, err = p.Decrypt(session, data)
	handlefatalerror(err)
	return plain, err
}

func handlefatalerror(err error) {
	if err != nil && fatalerrors[uint(err.(pkcs11.Error))] {
		log.Fatalf("goeleven FATAL error: %s\n", err.Error())
	}
}
