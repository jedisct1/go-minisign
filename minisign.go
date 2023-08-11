package minisign

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey struct {
	SignatureAlgorithm [2]byte
	KDFAlgorithm       [2]byte
	KDFRounds          [4]byte
	Salt               [16]byte
	Checksum           [8]byte
	KeyId              [8]byte
	PrivateKey         [64]byte
}

type PublicKey struct {
	SignatureAlgorithm [2]byte
	KeyId              [8]byte
	PublicKey          [32]byte
}

type Signature struct {
	UntrustedComment   string
	SignatureAlgorithm [2]byte
	KeyId              [8]byte
	Signature          [64]byte
	TrustedComment     string
	GlobalSignature    [64]byte
}

func NewPublicKey(publicKeyStr string) (PublicKey, error) {
	var publicKey PublicKey
	bin, err := base64.StdEncoding.DecodeString(publicKeyStr)
	if err != nil || len(bin) != 42 {
		return publicKey, errors.New("Invalid encoded public key")
	}
	copy(publicKey.SignatureAlgorithm[:], bin[0:2])
	copy(publicKey.KeyId[:], bin[2:10])
	copy(publicKey.PublicKey[:], bin[10:42])
	return publicKey, nil
}

func DecodePublicKey(in string) (PublicKey, error) {
	var publicKey PublicKey
	lines := strings.SplitN(in, "\n", 2)
	if len(lines) < 2 {
		return publicKey, errors.New("Incomplete encoded public key")
	}
	return NewPublicKey(lines[1])
}

func trimCarriageReturn(input string) string {
	return strings.TrimRight(input, "\r")
}

func DecodeSignature(in string) (Signature, error) {
	var signature Signature
	lines := strings.SplitN(in, "\n", 4)
	if len(lines) < 4 {
		return signature, errors.New("Incomplete encoded signature")
	}
	signature.UntrustedComment = trimCarriageReturn(lines[0])
	bin1, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(bin1) != 74 {
		return signature, errors.New("Invalid encoded signature")
	}
	signature.TrustedComment = trimCarriageReturn(lines[2])
	bin2, err := base64.StdEncoding.DecodeString(lines[3])
	if err != nil || len(bin2) != 64 {
		return signature, errors.New("Invalid encoded signature")
	}
	copy(signature.SignatureAlgorithm[:], bin1[0:2])
	copy(signature.KeyId[:], bin1[2:10])
	copy(signature.Signature[:], bin1[10:74])
	copy(signature.GlobalSignature[:], bin2)
	return signature, nil
}

func NewPublicKeyFromFile(file string) (PublicKey, error) {
	var publicKey PublicKey
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return publicKey, err
	}
	return DecodePublicKey(string(bin))
}

func NewSignatureFromFile(file string) (Signature, error) {
	var signature Signature
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return signature, err
	}
	return DecodeSignature(string(bin))
}

func (publicKey *PublicKey) Verify(bin []byte, signature Signature) (bool, error) {
	if publicKey.SignatureAlgorithm != [2]byte{'E', 'd'} {
		return false, errors.New("Incompatible signature algorithm")
	}
	prehashed := false
	if signature.SignatureAlgorithm[0] == 0x45 && signature.SignatureAlgorithm[1] == 0x64 {
		prehashed = false
	} else if signature.SignatureAlgorithm[0] == 0x45 && signature.SignatureAlgorithm[1] == 0x44 {
		prehashed = true
	} else {
		return false, errors.New("Unsupported signature algorithm")
	}
	if publicKey.KeyId != signature.KeyId {
		return false, errors.New("Incompatible key identifiers")
	}
	if !strings.HasPrefix(signature.TrustedComment, "trusted comment: ") {
		return false, errors.New("Unexpected format for the trusted comment")
	}

	if prehashed {
		h, _ := blake2b.New512(nil)
		h.Write(bin)
		bin = h.Sum(nil)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey.PublicKey[:]), bin, signature.Signature[:]) {
		return false, errors.New("Invalid signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey.PublicKey[:]), append(signature.Signature[:], []byte(signature.TrustedComment)[17:]...), signature.GlobalSignature[:]) {
		return false, errors.New("Invalid global signature")
	}
	return true, nil
}

func (publicKey *PublicKey) VerifyFromFile(file string, signature Signature) (bool, error) {
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return false, err
	}
	return publicKey.Verify(bin, signature)
}

func DecodePrivateKey(in string) (PrivateKey, error) {
	lines := strings.SplitN(in, "\n", 2)
	if len(lines) < 2 {
		return PrivateKey{}, errors.New("Incomplete encoded private key")
	}
	return NewPrivateKey(lines[1])
}

func NewPrivateKey(in string) (PrivateKey, error) {
	var privateKey PrivateKey
	keydata, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return privateKey, err
	}

	if len(keydata) != 104 {
		return privateKey, errors.New("Invalid encoded secret key")
	}

	if string(keydata[:2]) != "Ed" {
		return privateKey, errors.New("Unsupported signature scheme")
	}

	copy(privateKey.SignatureAlgorithm[:], keydata[:2])
	copy(privateKey.KDFAlgorithm[:], keydata[2:4])
	copy(privateKey.KDFRounds[:], keydata[4:8])
	copy(privateKey.Salt[:], keydata[8:24])
	copy(privateKey.Checksum[:], keydata[24:32])
	copy(privateKey.KeyId[:], keydata[32:40])
	copy(privateKey.PrivateKey[:], keydata[40:])
	return privateKey, nil
}

func NewPrivateKeyFromFile(file string) (PrivateKey, error) {
	var privateKey PrivateKey
	bin, err := ioutil.ReadFile(file)
	if err != nil {
		return privateKey, err
	}
	return DecodePrivateKey(string(bin))
}

func commentIsMoreThanOneLine(comment string) bool {
	firstLFIndex := strings.IndexByte(comment, 10)
	return (firstLFIndex >= 0 && firstLFIndex < len(comment)-1)
}

func (privateKey *PrivateKey) Sign(bin []byte, unTrustedComment string, trustedComment string) ([]byte, error) {
	out := bytes.NewBuffer(nil)

	rawSig := ed25519.Sign(privateKey.PrivateKey[:], bin)

	var sigdata []byte
	sigdata = append(sigdata, privateKey.SignatureAlgorithm[:]...)
	sigdata = append(sigdata, privateKey.KeyId[:]...)
	sigdata = append(sigdata, rawSig...)

	if unTrustedComment == "" {
		return nil, errors.New("Missing untrusted comment")
	}
	// Check that the trusted comment fits in one line
	if commentIsMoreThanOneLine(unTrustedComment) {
		return nil, errors.New("Untrusted comment must fit on a single line")
	}
	out.WriteString(fmt.Sprintf("untrusted comment: %s\n%s\n", unTrustedComment, base64.StdEncoding.EncodeToString(sigdata)))

	// Add the trusted comment if unavailable
	if trustedComment == "" {
		trustedComment = fmt.Sprintf("timestamp:%d", time.Now().Unix())
	}
	// Check that the trusted comment fits in one line
	if commentIsMoreThanOneLine(trustedComment) {
		return nil, errors.New("Trusted comment must fit on a single line")
	}

	var sigAndComment []byte
	sigAndComment = append(sigAndComment, rawSig...)
	sigAndComment = append(sigAndComment, []byte(trustedComment)...)
	out.WriteString(fmt.Sprintf("trusted comment: %s\n%s\n", trustedComment, base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey.PrivateKey[:], sigAndComment))))

	return out.Bytes(), nil
}
