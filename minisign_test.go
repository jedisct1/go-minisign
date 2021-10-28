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
