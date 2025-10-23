package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/namespaces"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strings"
)

type tokenResp struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

const (
	mediaManifestV2   = "application/vnd.docker.distribution.manifest.v2+json"
	mediaManifestList = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaOCIManifest  = "application/vnd.oci.image.manifest.v1+json"
	mediaOCIIndex     = "application/vnd.oci.image.index.v1+json"
)

type Descriptor struct {
	MediaType string        `json:"mediaType"`
	Digest    digest.Digest `json:"digest"`
	Size      int64         `json:"size,omitempty"`
	Platform  *Platform     `json:"platform,omitempty"`
}

type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Manifests     []Descriptor `json:"manifests"`
}

type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

var defaultUrl = "registry-1.docker.io"

func main() {

	var ctx = context.Background()
	ctxWithNamespace := namespaces.WithNamespace(ctx, "ocibaby")
	containerdClient, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		log.Fatal(err)
	}
	ctx, done, err := containerdClient.WithLease(ctxWithNamespace)
	if err != nil {
		log.Fatal(err)
	}

	defer done(ctx)

	println("Default Docker Registry URL is:", defaultUrl)

	urlStr := "https://" + defaultUrl + "/v2/"
	println("Docker Registry V2 API endpoint is:", urlStr)

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		log.Println(os.Stderr, "Error creating request:", err)
		os.Exit(1)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(os.Stderr, "Error making request:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var token string
	if resp.StatusCode == http.StatusUnauthorized {
		www := resp.Header.Get("WWW-Authenticate")
		log.Println("WWW-Authenticate:", www)
		log.Println("Received 401 Unauthorized. Token authentication required.")

		// For official images use the "library/<name>" repository namespace
		repo := "library/alpine"
		tok, err := getTokenFromWWW(www, repo, "pull")
		if err != nil {
			log.Println(os.Stderr, "Error getting token:", err)
			os.Exit(1)
		}
		token = tok

	} else if resp.StatusCode == http.StatusOK {
		// Anonymous access allowed; proceed without token
		log.Println("Registry returned 200 OK; proceeding anonymously (no token)")
	} else {
		log.Println(os.Stderr, "Unexpected response from registry:", resp.Status)
		os.Exit(1)
	}

	fmt.Println("Bearer token:", token)

	// Use the official library namespace for alpine
	configDigest, layers, err := FetchManifest(token, "library/alpine", "latest")
	if err != nil {
		log.Println(os.Stderr, "FetchManifest error:", err)
		os.Exit(1)
	}

	fmt.Println("Config digest:", configDigest)
	fmt.Println("Layers:")
	for _, d := range layers {
		fmt.Println(" -", d)
	}

	for _, entry := range layers {
		// Info expects a string reference
		info, err := containerdClient.ContentStore().Info(ctx, entry)
		if err == nil {
			// blob exists locally
			log.Println("Blob already present locally:", entry, "info:", info)
			continue
		}

		// If it's some error other than NotFound, log and continue
		if !errdefs.IsNotFound(err) {
			log.Println("Error getting content info for", entry, ":", err)
			continue
		}

		// Not found -> fetch
		log.Println("Content info for", entry, "not found locally. Proceeding to fetch.")
		if err := fetchAndStreamBlob(ctx, containerdClient.ContentStore(), token, "library/alpine", entry); err != nil {
			log.Println("Error fetching and streaming blob", entry, ":", err)
			continue
		}

		// Verify it was written
		info, err = containerdClient.ContentStore().Info(ctx, entry)
		if err != nil {
			log.Println("Fetch succeeded but Info failed for", entry, ":", err)
		} else {
			log.Println("Successfully stored blob:", entry, "info:", info)
		}
	}
}

// getTokenFromWWW parses a WWW-Authenticate header and fetches a token from the realm.
// repo is the repository name (e.g. "library/alpine") and action is usually "pull" or "pull,push".
func getTokenFromWWW(www, repo, action string) (string, error) {
	if www == "" {
		return "", fmt.Errorf("empty WWW-Authenticate header")
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(www, prefix) {
		return "", fmt.Errorf("unsupported WWW-Authenticate: %s", www)
	}

	rest := strings.TrimPrefix(www, prefix)
	m := map[string]string{}
	for _, p := range strings.Split(rest, ",") {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := kv[0]
		v := strings.Trim(kv[1], `"`)
		m[k] = v
	}

	realm := m["realm"]
	if realm == "" {
		return "", fmt.Errorf("realm missing in WWW-Authenticate")
	}

	u, err := url.Parse(realm)
	if err != nil {
		return "", err
	}
	q := u.Query()
	if s := m["service"]; s != "" {
		q.Set("service", s)
	}
	if sc := m["scope"]; sc != "" {
		q.Set("scope", sc)
	} else {
		q.Set("scope", fmt.Sprintf("repository:%s:%s", repo, action))
	}
	u.RawQuery = q.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint responded: %s %s", resp.Status, strings.TrimSpace(string(b)))
	}

	var tr tokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", err
	}
	if tr.Token != "" {
		return tr.Token, nil
	}
	if tr.AccessToken != "" {
		return tr.AccessToken, nil
	}
	return "", fmt.Errorf("no token in response")
}

func FetchManifest(token, imageName, tag string) (configDigest string, layerDigests []digest.Digest, err error) {
	accept := strings.Join([]string{
		mediaManifestList,
		mediaOCIIndex,
		mediaManifestV2,
		mediaOCIManifest,
	}, ", ")

	// helper to GET a manifest (by ref or digest) and return body + content-type
	get := func(ref string) (body []byte, contentType string, err error) {
		url := "https://" + defaultUrl + "/v2/" + imageName + "/manifests/" + ref
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("Accept", accept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("manifest request failed: %s", resp.Status)
		}
		ct := resp.Header.Get("Content-Type")
		b, err := io.ReadAll(resp.Body)
		return b, ct, err
	}

	b, ct, err := get(tag)
	if err != nil {
		return "", nil, err
	}
	ct = strings.ToLower(ct)

	if strings.Contains(ct, "manifest.list") || strings.Contains(ct, "index") {
		var idx Index
		if err := json.Unmarshal(b, &idx); err != nil {
			return "", nil, fmt.Errorf("failed to decode index: %w", err)
		}

		targetOS := runtime.GOOS
		targetArch := runtime.GOARCH

		// If running on macOS, the container images are typically linux/*
		if targetOS == "darwin" {
			targetOS = "linux"
		}

		// arch aliases to handle variations like aarch64 vs arm64
		tarchAliases := func(a string) []string {
			switch a {
			case "arm64":
				return []string{"arm64", "aarch64"}
			case "amd64":
				return []string{"amd64", "x86_64"}
			default:
				return []string{a}
			}
		}
		wantedArchs := tarchAliases(targetArch)

		// helper to check if candidate arch matches our wanted arch aliases
		archMatch := func(cand string) bool {
			for _, a := range wantedArchs {
				if cand == a {
					return true
				}
			}
			return false
		}

		var chosen *Descriptor
		for _, d := range idx.Manifests {
			if d.Platform == nil {
				continue
			}
			if d.Platform.OS == targetOS && archMatch(d.Platform.Architecture) {
				chosen = &Descriptor{MediaType: d.MediaType, Digest: d.Digest}
				break
			}
		}

		// 2) OS-only match
		if chosen == nil {
			for _, d := range idx.Manifests {
				if d.Platform == nil {
					continue
				}
				if d.Platform.OS == targetOS {
					chosen = &Descriptor{MediaType: d.MediaType, Digest: d.Digest}
					break
				}
			}
		}

		// 3) Arch-only match
		if chosen == nil {
			for _, d := range idx.Manifests {
				if d.Platform == nil {
					continue
				}
				if archMatch(d.Platform.Architecture) {
					chosen = &Descriptor{MediaType: d.MediaType, Digest: d.Digest}
					break
				}
			}
		}

		// 4) Fallback to first manifest entry
		if chosen == nil && len(idx.Manifests) > 0 {
			chosen = &Descriptor{MediaType: idx.Manifests[0].MediaType, Digest: idx.Manifests[0].Digest}
		}

		if chosen == nil {
			return "", nil, fmt.Errorf("no matching manifest for platform %s/%s", targetOS, targetArch)
		}

		b, ct, err = get(string(chosen.Digest))
		if err != nil {
			return "", nil, err
		}
	}

	// Parse manifest (single image manifest)
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return "", nil, fmt.Errorf("failed to decode manifest: %w", err)
	}

	if m.Config.Digest == "" {
		return "", nil, fmt.Errorf("manifest has no config digest")
	}

	configDigest = string(m.Config.Digest)
	layerDigests = make([]digest.Digest, 0, len(m.Layers))
	for _, l := range m.Layers {
		if l.Digest != "" {
			layerDigests = append(layerDigests, l.Digest)
		}
	}
	return configDigest, layerDigests, nil
}

// Call this from the loop where you currently have the TODO.
// imageName should be the repository name (e.g. "library/alpine").
func fetchAndStreamBlob(ctx context.Context, cs content.Store, token, imageName string, dgst digest.Digest) error {
	blobUrl := "https://" + defaultUrl + "/v2/" + imageName + "/blobs/" + dgst.String()
	req, err := http.NewRequest("GET", blobUrl, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// optional: request chunked transfer or any particular Accept if needed
	req.Header.Set("Accept", "*/*")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("blob GET %s: %s %s", dgst.String(), resp.Status, strings.TrimSpace(string(b)))
	}

	contentlength := resp.Header.Get("Content-Length")
	sizeInBytes, err := strconv.ParseInt(contentlength, 10, 64)
	if err != nil {
		return fmt.Errorf("error parsing content length: %v", err)
	}

	desc := v1.Descriptor{
		MediaType: resp.Header.Get("Content-Type"),
		Digest:    dgst,
		Size:      sizeInBytes,
	}

	err = content.WriteBlob(ctx, cs, imageName, resp.Body, desc)
	return err
}
