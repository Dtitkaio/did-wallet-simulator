package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sync"
)

// VerificationMethod represents cryptographic keys or other methods used for digital signatures, encryption, etc.
type VerificationMethod struct {
	ID         string
	Type       string // Type needs to be registered in the DID Specification Registries.
	Controller string
	PublicKey  []byte
}

// DIDDocument represents the document containing all relevant information about the DID.
type DIDDocument struct {
	Context               string // References to W3C urls that explain the terminology in this document.
	ID                    string
	Controller            string
	VerificationMethods   []VerificationMethod
	VerificationRelations map[string][]string // Relating methods to their purposes like authentication, assertionMethod, etc.
	ServiceEndPoints      map[string]string // For communicatino of other entities with the DID subject(e.g. me). For instance, LinkedIn profile, Paypay account, etc.
}

// VerifiableDataRegistry simulates a simple registry for DIDs.
type VerifiableDataRegistry struct {
	mu      sync.Mutex
	records map[string]DIDDocument
}

// DIDResolver simulates resolving a DID to a DID document.
type DIDResolver struct {
	registry *VerifiableDataRegistry
}

// NewDIDController creates a new controller with a public-private key pair.
func NewDIDController() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// RegisterDID simulates registering the DID in a verifiable data registry.
func (registry *VerifiableDataRegistry) RegisterDID(doc DIDDocument) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.records[doc.ID] = doc
	return nil
}

// ResolveDID simulates resolving the DID in the registry.
func (resolver *DIDResolver) ResolveDID(did string) (*DIDDocument, bool) {
	resolver.registry.mu.Lock()
	defer resolver.registry.mu.Unlock()
	doc, found := resolver.registry.records[did]
	return &doc, found
}

// main function to simulate the whole process.
func main() {
	controllerKey, err := NewDIDController()
	if err != nil {
		fmt.Println("Error creating controller:", err)
		return
	}
	
	publicKeyBytes := elliptic.Marshal(elliptic.P256(), controllerKey.PublicKey.X, controllerKey.PublicKey.Y)
	verMethod := VerificationMethod{
		ID:         "key1",
		Type:       "EcdsaSecp256k1VerificationKey2019",
		Controller: "subject1",
		PublicKey:  publicKeyBytes,
	}

	subjectID := "subject1"
	did := "did:example:" + subjectID
	doc := DIDDocument{
		Context:    "https://www.w3.org/ns/did/v1",
		ID:         did,
		Controller: subjectID,
		VerificationMethods:   []VerificationMethod{verMethod},
		VerificationRelations: map[string][]string{"authentication": {"key1"}},
		ServiceEndPoints:      map[string]string{"profile": "https://profile.example.com/subject1"},
	}

	registry := VerifiableDataRegistry{
		records: make(map[string]DIDDocument),
	}
	resolver := DIDResolver{registry: &registry}

	err = registry.RegisterDID(doc)
	if err != nil {
		fmt.Println("Error registering DID:", err)
		return
	}

	verifiedDoc, found := resolver.ResolveDID(did)
	if !found {
		fmt.Println("DID not found in registry")
		return
	}

	// Output the verified document.
	docJSON, _ := json.MarshalIndent(verifiedDoc, "", "  ")
	fmt.Println("Resolved DID Document:", string(docJSON))
}
