package main

import (
	"fmt"
	"github.com/miekg/pkcs11"
	"log"
)

func main() {
	//Specify your YubiKey PIN
	yubiKeyDefaultPin := `123456`

	//Specify the path to onepin-opensc-pkcs11.dll/so
	modulePath := `C:\Program Files\OpenSC Project\OpenSC\pkcs11\onepin-opensc-pkcs11.dll`

	//Specify th slotID in your environment
	var slotId uint = 5

	p := pkcs11.New(modulePath)
	p.Initialize()
	defer p.Destroy()
	defer p.Finalize()

	session, err := p.OpenSession(slotId, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		log.Fatalf("failed to OpenSession: %v\n", err)
	}

	defer p.CloseSession(session)

	err = p.Login(session, pkcs11.CKU_USER, yubiKeyDefaultPin)
	if err != nil {
		log.Fatalf("failed to Login: %v\n", err)
	}

	defer p.Logout(session)

	message := []byte("Hello World.")

	var msgDigest []byte
	p.DigestInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256, nil)})
	if err != nil {
		log.Fatalf("failed to DigestInit: %v\n", err)
	}


	err = p.DigestUpdate(session, message)
	if err != nil {
		log.Fatalf("failed to DigestUpdate: %v\n", err)
	}

	msgDigest, err = p.DigestFinal(session)
	if err != nil {
		log.Fatalf("failed to DigestFinal: %v\n", err)
	}

	fmt.Printf("SHA256 Digest: %x\n", msgDigest)


	privateKeyObjectHandler, publicKeyObjectHandler := loadKeyPairObjectHandles(p, session)


	//[RFC8017] https://tools.ietf.org/html/rfc8017#section-8.2
	toBeSignedData := []byte("Hello World. again")

	var signature []byte
	err = p.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, privateKeyObjectHandler)
	if err != nil {
		log.Fatalf("failed to SignInit: %v\n", err)
	}

	signature, err = p.Sign(session, toBeSignedData)
	if err != nil {
		log.Fatalf("failed to Sign: %v\n", err)
	}

	fmt.Printf("Signature: %x\n", signature)


	err = p.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SHA256_RSA_PKCS, nil)}, publicKeyObjectHandler)
	if err != nil {
		log.Fatalf("failed to VerifyInit: %v\n", err)
	}

	err = p.Verify(session, toBeSignedData, signature)
	if err != nil {
		log.Fatalf("failed to Verify: %v\n", err)
	}

	log.Println("Verify OK\n")

}

func loadKeyPairObjectHandles(p *pkcs11.Ctx, session pkcs11.SessionHandle) (pkcs11.ObjectHandle, pkcs11.ObjectHandle) {
	privateKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	}

	publicKeyTemplate := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	}

	err := p.FindObjectsInit(session, privateKeyTemplate)
	if err != nil {
		log.Fatalf("failed to FindObjectsInit: %v\n", err)
	}

	objects, _, err := p.FindObjects(session, 1)
	if err != nil {
		log.Fatalf("failed to FindObjects: %v\n", err)
	}

	err = p.FindObjectsFinal(session)
	if err != nil {
		log.Fatalf("failed to FindObjectsFinal: %v\n", err)
	}

	if len(objects) < 1 {
		log.Fatalf("failed to find private key handler ocject: %v\n", objects)
	}
	pvk := objects[0]



	err = p.FindObjectsInit(session, publicKeyTemplate)
	if err != nil {
		log.Fatalf("failed to FindObjectsInit: %v\n", err)
	}
	objects, _, err = p.FindObjects(session, 1)

	if err != nil {
		log.Fatalf("failed to FindObjects: %v\n", err)
	}


	err = p.FindObjectsFinal(session)
	if err != nil {
		log.Fatalf("failed to FindObjectsFinal: %v\n", objects)
	}

	if len(objects) < 1 {
		log.Fatalf("failed to find public key handler ocject: %v\n", objects)
	}
	puk := objects[0]


	return pvk, puk
}
