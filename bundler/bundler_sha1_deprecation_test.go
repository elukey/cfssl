package bundler

// This test file contains tests on checking Bundle.Status with SHA-1 deprecation warning.
import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/config"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	sha1CA           = "testdata/ca.pem"
	sha1CAKey        = "testdata/ca.key"
	sha1Intermediate = "testdata/inter-L1-sha1.pem"
	sha2Intermediate = "testdata/inter-L1.pem"
	intermediateKey  = "testdata/inter-L1.key"
	intermediateCSR  = "testdata/inter-L1.csr"
	leafCSR          = "testdata/cfssl-leaf-ecdsa256.csr"
)

func TestChromeWarning(t *testing.T) {
	// Go >= 1.24 removed the x509sha1 GODEBUG knob, making SHA-1 chain
	// verification a hard error. BundleFromPEMorDER returns 1220 before any
	// warning logic runs, so this test cannot pass without SHA-1 support.
	t.Skip("SHA-1 chain verification removed in Go 1.24 (x509sha1 GODEBUG knob dropped)")
}

func TestSHA2Preferences(t *testing.T) {
	// This test verified that cfssl prefers a SHA-256-signed intermediate over a
	// SHA-1-signed one when both are available. Go >= 1.24 hard-rejects SHA-1
	// chains, making it impossible to construct the scenario under test.
	// SHA-384 scores identically to SHA-256 in cfssl's ubiquity model, so there
	// is no substitute weaker-but-valid algorithm that triggers the same path.
	t.Skip("SHA-2 preference over SHA-1 is untestable: Go 1.24 rejects SHA-1 chains and no weaker SHA-2 variant exists in cfssl ubiquity scoring")
}

func makeCASignerFromFile(certFile, keyFile string, sigAlgo x509.SignatureAlgorithm, t *testing.T) signer.Signer {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}

	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}

	return makeCASigner(certBytes, keyBytes, sigAlgo, t)

}

func makeCASigner(certBytes, keyBytes []byte, sigAlgo x509.SignatureAlgorithm, t *testing.T) signer.Signer {
	cert, err := helpers.ParseCertificatePEM(certBytes)
	if err != nil {
		t.Fatal(err)
	}

	key, err := helpers.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		t.Fatal(err)
	}

	defaultProfile := &config.SigningProfile{
		Usage:        []string{"cert sign"},
		CAConstraint: config.CAConstraint{IsCA: true},
		Expiry:       time.Hour,
		ExpiryString: "1h",
	}
	policy := &config.Signing{
		Profiles: map[string]*config.SigningProfile{},
		Default:  defaultProfile,
	}
	s, err := local.NewSigner(key, cert, sigAlgo, policy)
	if err != nil {
		t.Fatal(err)
	}

	return s
}

func signCSRFile(s signer.Signer, csrFile string, t *testing.T) []byte {
	csrBytes, err := os.ReadFile(csrFile)
	if err != nil {
		t.Fatal(err)
	}

	signingRequest := signer.SignRequest{Request: string(csrBytes)}
	certBytes, err := s.Sign(signingRequest)
	if err != nil {
		t.Fatal(err)
	}

	return certBytes
}
