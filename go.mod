module github.com/wayf-dk/goeleven

go 1.22

require (
	github.com/miekg/pkcs11 v1.1.1
	x.config v0.0.0-00010101000000-000000000000
)

require (
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
)

replace x.config => ../hybrid-config
