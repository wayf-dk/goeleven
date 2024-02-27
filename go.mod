module github.com/wayf-dk/goeleven

go 1.22.0

require (
	github.com/miekg/pkcs11 v1.1.1
	x.config v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/crypto v0.20.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
)

replace x.config => ../hybrid-config
