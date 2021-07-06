package minisign

import (
	"testing"
)

var (
	testPKey = "untrusted comment: minisign public key\nRWTAPRW2qy9FjsBiMFGCEFv9Jk3iPhAh7tZb+VOFmtmBxDyHrFT8kZuT"
	testSKey = "untrusted comment: minisign secret key\nRWRCSwAAAABVN5lr2JViGBN8DhX3/Qb/0g0wBdsNAR/APRW2qy9Fjsfr12sK2cd3URUFis1jgzQzaoayK8x4syT4G3Gvlt9RwGIwUYIQW/0mTeI+ECHu1lv5U4Wa2YHEPIesVPyRm5M="
)

func TestRoundTrip(t *testing.T) {
	pkey, err := DecodePublicKey(testPKey)
	if err != nil {
		t.Fatalf("error decoding the public key: %v", err)
	}
	skey, err := DecodePrivateKey(testSKey)
	if err != nil {
		t.Fatalf("error decoding the private key: %v", err)
	}

	sig, err := skey.Sign([]byte("hello"), "verify with minisign", "")
	if err != nil {
		t.Fatalf("error signing: %v", err)
	}

	signature, err := DecodeSignature(string(sig))
	if err != nil {
		t.Fatalf("error when decoding signature: %v", err)
	}

	ok, err := pkey.Verify([]byte("hello"), signature)
	if err != nil {
		t.Fatalf("error verifying signature: %v", err)
	}
	if !ok {
		t.Fatal("signature could not be verified")
	}
}
