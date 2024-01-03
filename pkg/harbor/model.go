package harbor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"time"
)

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevUnknown
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	return severityToString[s]
}

var severityToString = map[Severity]string{
	SevUnknown:  "Unknown",
	SevLow:      "Low",
	SevMedium:   "Medium",
	SevHigh:     "High",
	SevCritical: "Critical",
}

var stringToSeverity = map[string]Severity{
	"Unknown":  SevUnknown,
	"Low":      SevLow,
	"Medium":   SevMedium,
	"High":     SevHigh,
	"Critical": SevCritical,
}

// MarshalJSON marshals the Severity enum value as a quoted JSON string.
func (s Severity) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(severityToString[s])
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// UnmarshalJSON unmarshals quoted JSON string to the Severity enum value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var value string
	err := json.Unmarshal(b, &value)
	if err != nil {
		return err
	}
	*s = stringToSeverity[value]
	return nil
}

type Registry struct {
	URL           string `json:"url"`
	Authorization string `json:"authorization"`
}

type Artifact struct {
	Repository string `json:"repository"`
	Digest     string `json:"digest"`
	MimeType   string `json:"mime_type,omitempty"`
}

type ScanRequest struct {
	Registry            Registry            `json:"registry"`
	Artifact            Artifact            `json:"artifact"`
	EnabledCapabilities []EnabledCapability `json:"enabled_capabilities"`
}

type EnabledCapability struct {
	Type             string            `json:"type"`
	ProduceMimeTypes []string          `json:"produce_mime_types,omitempty"`
	Parameters       map[string]string `json:"parameters,omitempty"`
}

// GetImageRef returns Docker image reference for this ScanRequest.
// Example: core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246ca119d16111eb62f7302b2ff66d51e373c2bb209f8a1f3b9e
func (c ScanRequest) GetImageRef() (imageRef string, insecureRegistry bool, err error) {
	registryURL, err := url.Parse(c.Registry.URL)
	if err != nil {
		err = fmt.Errorf("parsing registry URL: %w", err)
		return
	}

	port := registryURL.Port()
	if port == "" && registryURL.Scheme == "http" {
		port = "80"
	}
	if port == "" && registryURL.Scheme == "https" {
		port = "443"
	}

	imageRef = fmt.Sprintf("%s:%s/%s@%s", registryURL.Hostname(), port, c.Artifact.Repository, c.Artifact.Digest)
	insecureRegistry = "http" == registryURL.Scheme
	return
}

type ScanResponse struct {
	ID string `json:"id"`
}

type ScanReport struct {
	GeneratedAt     time.Time           `json:"generated_at"`
	Artifact        Artifact            `json:"artifact"`
	Scanner         Scanner             `json:"scanner"`
	Severity        Severity            `json:"severity"`
	Vulnerabilities []VulnerabilityItem `json:"vulnerabilities"`
}

type Layer struct {
	Digest string `json:"digest,omitempty"`
	DiffID string `json:"diff_id,omitempty"`
}

type CVSSDetails struct {
	ScoreV2  *float32 `json:"score_v2,omitempty"`
	ScoreV3  *float32 `json:"score_v3,omitempty"`
	VectorV2 string   `json:"vector_v2"`
	VectorV3 string   `json:"vector_v3"`
}

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID               string                 `json:"id"`
	Pkg              string                 `json:"package"`
	Version          string                 `json:"version"`
	FixVersion       string                 `json:"fix_version,omitempty"`
	Severity         Severity               `json:"severity"`
	Description      string                 `json:"description"`
	Links            []string               `json:"links"`
	Layer            *Layer                 `json:"layer"` // Not defined by Scanners API
	PreferredCVSS    *CVSSDetails           `json:"preferred_cvss,omitempty"`
	CweIDs           []string               `json:"cwe_ids,omitempty"`
	VendorAttributes map[string]interface{} `json:"vendor_attributes,omitempty"`
}

type ScannerAdapterMetadata struct {
	Scanner      Scanner           `json:"scanner"`
	Capabilities []Capability      `json:"capabilities"`
	Properties   map[string]string `json:"properties"`
}

type Scanner struct {
	Name    string `json:"name"`
	Vendor  string `json:"vendor"`
	Version string `json:"version"`
}

type Capability struct {
	ConsumesMIMETypes []string `json:"consumes_mime_types"`
	ProducesMIMETypes []string `json:"produces_mime_types"`
}

// Error holds the information about an error, including metadata about its JSON structure.
type Error struct {
	HTTPCode int    `json:"-"`
	Message  string `json:"message"`
}

// SBOMReport is a software bill of materials report.
// defined in the swagger https://raw.githubusercontent.com/goharbor/pluggable-scanner-spec/master/api/spec/scanner-adapter-openapi-v1.2.yaml
type SBOMReport struct {
	GeneratedAt      time.Time              `json:"generated_at"`
	Artifact         Artifact               `json:"artifact"`
	Scanner          Scanner                `json:"scanner"`
	VendorAttributes map[string]interface{} `json:"vendor_attributes,omitempty"`
	MediaType        string                 `json:"media_type"`
	SBOM             string                 `json:"sbom"`
}

// SBOMSPDXReport is a software bill of materials report with SPDX format
// schema defined in https://github.com/spdx/spdx-spec/blob/master/schemas/spdx-schema.json
type SBOMSPDXReport struct {
	SpdxVersion string `json:"spdxVersion"`
	DataLicense string `json:"dataLicense"`
	// SPDXID is a unique identifier of the SPDX document
	SPDXID string `json:"spdxID"`
	Name   string `json:"name"`
	// SPDXDocumentNamespace is a unique namespace of the SPDX document
	SPDXDocumentNamespace string       `json:"documentNamespace"`
	CreationInfo          CreationInfo `json:"creationInfo"`
	// Packages includes all packages contained in the SPDX document
	Packages []Package `json:"packages"`
	// Relationships         []string     `json:"relationships"`
}

type CreationInfo struct {
	LicenseListVersion string    `json:"licenseListVersion"`
	Creators           []string  `json:"creators"`
	Created            time.Time `json:"created"`
}

type Package struct {
	Name                  string   `json:"name"`
	SPDXID                string   `json:"SPDXID"`
	VersionInfo           string   `json:"versionInfo"`
	DownloadLocation      string   `json:"downloadLocation"`
	CopyRightText         string   `json:"copyRightText"`
	primaryPackagePurpose string   `json:"primaryPackagePurpose"`
	Checksums             []string `json:"checksums"`
}

// SBOMCycloneDXReport is a software bill of materials report with CycloneDX format
// schema defined in https://cyclonedx.org/docs/1.5/json/#bomFormat
type SBOMCycloneDXReport struct {
	BOMFormat string `json:"bomFormat"`
	// SpecVersion is the version of the CycloneDX specification
	SpecVersion string `json:"specVersion"`
	// SerialNumber is a unique identifier for the BOM
	SerialNumber string `json:"serialNumber"`
	// Version is the version of the BOM
	Version string `json:"version"`
	// Metadata is a list of metadata entries
	Metadata Metadata `json:"metadata"`
	// Components is a list of components
	Components []Component `json:"components"`
}

type Metadata struct {
	// Timestamp is the timestamp of the BOM
	Timestamp time.Time `json:"timestamp"`
}

type Component struct {
	// Type is the type of the component
	Type string `json:"type"`
	// BOMRef is a reference to the BOM
	BOMRef string `json:"bom-ref"`
	// Name is the name of the component
	Name string `json:"name"`
	// Version is the version of the component
	Version string `json:"version"`
	// PURL is the package URL of the component
	PURL string `json:"purl"`
	// Licenses is a list of licenses of the component
	Licenses []License `json:"licenses"`
}

type License struct {
	// Name is the name of the license
	Name string `json:"name"`
}
