package minisign

import "testing"

func TestLegacy(t *testing.T) {
	pk, err := NewPublicKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3")
	if err != nil {
		t.Fatal(err)
	}
	sigStr := "untrusted comment: signature from minisign secret key\nRWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=\ntrusted comment: timestamp:1635442742\tfile:test\n0YteLgV960ia80vnA/fHbvkyjl/IoP/HNOCaZfrF0CdhAlp7ok+Tpkya+VpWPX5C/Is3q8a/kEDSY7fBmmgJCg==\n"
	sig, err := DecodeSignature(sigStr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pk.Verify([]byte("test"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("signature verification failed")
	}
}

func TestPrehashed(t *testing.T) {
	pk, err := NewPublicKey("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3")
	if err != nil {
		t.Fatal(err)
	}
	sigStr := "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1635443258\tfile:test\thashed\n/cj37GK60vryibFn+ftOgbCvW9NKhKYgjVpFFQUcWPAnjO23wrvVDTt7cloNC06maoBli9q6qwZDXXoaxweICQ==\n"
	sig, err := DecodeSignature(sigStr)
	if err != nil {
		t.Fatal(err)
	}
	v, err := pk.Verify([]byte("test"), sig)
	if err != nil {
		t.Fatal(err)
	}
	if !v {
		t.Fatal("signature verification failed")
	}
}

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
