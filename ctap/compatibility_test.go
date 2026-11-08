package ctap

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/bulwarkid/virtual-fido/cose"
	"github.com/bulwarkid/virtual-fido/crypto"
	"github.com/bulwarkid/virtual-fido/fido_client"
	"github.com/bulwarkid/virtual-fido/identities"
	"github.com/bulwarkid/virtual-fido/util"
	"github.com/bulwarkid/virtual-fido/webauthn"
	"github.com/fxamacker/cbor/v2"
)

type memoryVault struct{ data []byte }

func (v *memoryVault) SaveData(data []byte) { v.data = data }
func (v *memoryVault) RetrieveData() []byte { return v.data }
func (v *memoryVault) Passphrase() string   { return "isolated-test-vault" }

type approveTestActions struct{}

func (approveTestActions) ApproveClientAction(fido_client.ClientAction, fido_client.ClientActionRequestParams) bool {
	return true
}

func realTestClient(t *testing.T, vault *memoryVault) *fido_client.DefaultFIDOClient {
	t.Helper()
	key, err := identities.CreateCAPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := identities.CreateSelfSignedCA(key)
	if err != nil {
		t.Fatal(err)
	}
	return fido_client.NewDefaultClient(cert, key, [32]byte{}, true, approveTestActions{}, vault)
}

func exchange(t *testing.T, server *CTAPServer, command ctapCommand, args any, want ctapStatusCode, result any) {
	t.Helper()
	response := server.HandleMessage(append([]byte{byte(command)}, util.MarshalCBOR(args)...))
	if len(response) == 0 || response[0] != byte(want) {
		t.Fatalf("command %x: status %x, want %x", command, response, want)
	}
	if result != nil {
		if err := cbor.Unmarshal(response[1:], result); err != nil {
			t.Fatal(err)
		}
	}
}

func registration() makeCredentialArgs {
	return makeCredentialArgs{
		ClientDataHash:   crypto.HashSHA256([]byte("registration")),
		RP:               &webauthn.PublicKeyCredentialRPEntity{ID: "webauthn.example", Name: "WebAuthn test"},
		User:             &webauthn.PublicKeyCrendentialUserEntity{ID: []byte("alice"), Name: "Alice"},
		PubKeyCredParams: []webauthn.PublicKeyCredentialParams{{Type: "public-key", Algorithm: cose.COSE_ALGORITHM_ID_ES256}},
	}
}

func TestAssertionCounterSurvivesRestart(t *testing.T) {
	vault := &memoryVault{}
	client := realTestClient(t, vault)
	server := NewCTAPServer(client)
	var made makeCredentialResponse
	exchange(t, server, ctapCommandMakeCredential, registration(), ctap1ErrSuccess, &made)
	previous := uint32(0)
	for i := 0; i < 2; i++ {
		if i == 1 {
			client = realTestClient(t, vault)
			server = NewCTAPServer(client)
		}
		args := getAssertionArgs{RPID: "webauthn.example", ClientDataHash: crypto.HashSHA256([]byte("login"))}
		var response getAssertionResponse
		exchange(t, server, ctapCommandGetAssertion, args, ctap1ErrSuccess, &response)
		counter := binary.BigEndian.Uint32(response.AuthenticatorData[33:37])
		if counter <= previous {
			t.Fatalf("counter %d did not advance from %d (restart=%v)", counter, previous, i == 1)
		}
		previous = counter
		if !client.Identities()[0].PrivateKey.Public().Verify(append(response.AuthenticatorData, args.ClientDataHash...), response.Signature) {
			t.Fatal("invalid assertion signature")
		}
		if !bytes.Equal(response.User.ID, []byte("alice")) {
			t.Fatal("user handle lost")
		}
	}
}

func TestPINProtocolAndVerifiedAssertion(t *testing.T) {
	client := realTestClient(t, &memoryVault{})
	server := NewCTAPServer(client)
	var agreement clientPINResponse
	exchange(t, server, ctapCommandClientPIN, clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetKeyAgreement}, ctap1ErrSuccess, &agreement)
	key := agreement.KeyAgreement
	if key.Curve != 1 || len(key.X) != 32 || len(key.Y) != 32 {
		t.Fatalf("invalid P-256 key agreement: curve=%d x=%d y=%d", key.Curve, len(key.X), len(key.Y))
	}
	remote := crypto.GenerateECDHKey()
	shared := crypto.HashSHA256(remote.ECDH(util.BytesToBigInt(key.X), util.BytesToBigInt(key.Y)))
	remoteKey := &cose.COSEEC2Key{KeyType: 2, Algorithm: -25, Curve: 1, X: remote.X.FillBytes(make([]byte, 32)), Y: remote.Y.FillBytes(make([]byte, 32))}
	paddedPIN := make([]byte, 64)
	copy(paddedPIN, "123456")
	encodedPIN := crypto.EncryptAESCBC(shared, paddedPIN)
	exchange(t, server, ctapCommandClientPIN, clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPINSubcommandSetPIN, KeyAgreement: remoteKey, NewPINEncoding: encodedPIN, PINUVAuthParam: server.derivePINAuth(shared, encodedPIN)}, ctap1ErrSuccess, nil)
	var token clientPINResponse
	exchange(t, server, ctapCommandClientPIN, clientPINArgs{PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetPINToken, KeyAgreement: remoteKey, PINHashEncoding: crypto.EncryptAESCBC(shared, crypto.HashSHA256([]byte("123456"))[:16])}, ctap1ErrSuccess, &token)
	plainToken := crypto.DecryptAESCBC(shared, token.PinToken)
	args := registration()
	args.PINUVAuthProtocol = 1
	args.PINUVAuthParam = server.derivePINAuth(plainToken, args.ClientDataHash)
	var made makeCredentialResponse
	exchange(t, server, ctapCommandMakeCredential, args, ctap1ErrSuccess, &made)
	login := getAssertionArgs{RPID: args.RP.ID, ClientDataHash: crypto.HashSHA256([]byte("verified login")), PINUVAuthProtocol: 1}
	login.PINUVAuthParam = server.derivePINAuth(plainToken, login.ClientDataHash)
	var response getAssertionResponse
	exchange(t, server, ctapCommandGetAssertion, login, ctap1ErrSuccess, &response)
	if response.AuthenticatorData[32]&5 != 5 || made.AuthData[32]&5 != 5 {
		t.Fatal("PIN authentication must set UP and UV")
	}
	login.PINUVAuthParam[0] ^= 1
	exchange(t, server, ctapCommandGetAssertion, login, ctap2ErrPINAuthInvalid, nil)
}

func TestMalformedCTAPDoesNotPanic(t *testing.T) {
	server := NewCTAPServer(&dummyCTAPClient{})
	for _, message := range [][]byte{nil, {0xff}, {1, 0xff}, {1, 0xa0}, {2, 0xa0}, {6, 0xff}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("message %x panicked: %v", message, r)
				}
			}()
			response := server.HandleMessage(message)
			if len(response) != 1 || response[0] == 0 {
				t.Errorf("message %x: expected error, got %x", message, response)
			}
		}()
	}
}

func TestExcludedCredentialAndUnsupportedUV(t *testing.T) {
	client := realTestClient(t, &memoryVault{})
	server := NewCTAPServer(client)
	args := registration()
	exchange(t, server, ctapCommandMakeCredential, args, ctap1ErrSuccess, nil)
	args.ExcludeList = []webauthn.PublicKeyCredentialDescriptor{client.Identities()[0].CTAPDescriptor()}
	exchange(t, server, ctapCommandMakeCredential, args, ctap2ErrCredentialExcluded, nil)
	if len(client.Identities()) != 1 {
		t.Fatal("excluded credential was duplicated")
	}
	args.Options = &makeCredentialOptions{UserVerification: true}
	exchange(t, server, ctapCommandMakeCredential, args, ctap2ErrInvalidOption, nil)
	exchange(t, server, ctapCommandGetAssertion, getAssertionArgs{RPID: args.RP.ID, ClientDataHash: args.ClientDataHash, Options: getAssertionOptions{UserVerification: true}}, ctap2ErrInvalidOption, nil)
}

func TestPINBlockSurvivesRestart(t *testing.T) {
	vault := &memoryVault{}
	client := realTestClient(t, vault)
	client.SetPIN([]byte("123456"))
	client.SetPINRetries(0)
	client = realTestClient(t, vault)
	if client.PINRetries() != 0 {
		t.Fatal("restart cleared PIN block")
	}
	server := NewCTAPServer(client)
	remote := crypto.GenerateECDHKey()
	exchange(t, server, ctapCommandClientPIN, clientPINArgs{
		PINUVAuthProtocol: 1, SubCommand: clientPinSubcommandGetPINToken,
		KeyAgreement:    &cose.COSEEC2Key{KeyType: 2, Algorithm: -25, Curve: 1, X: remote.X.FillBytes(make([]byte, 32)), Y: remote.Y.FillBytes(make([]byte, 32))},
		PINHashEncoding: make([]byte, 16),
	}, ctap2ErrPINBlocked, nil)
}
