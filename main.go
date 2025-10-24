package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/namespaces"
	"github.com/opencontainers/go-digest"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"

	"io"
	"log"
	"net/http"
	neturl "net/url"
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
	ctxWithNamespace := namespaces.WithNamespace(ctx, "default")
	containerdClient, err := containerd.New("/run/containerd/containerd.sock")
	if err != nil {
		log.Fatal(err)
	}
	ctx, done, err := containerdClient.WithLease(ctxWithNamespace)
	if err != nil {
		log.Fatal(err)
	}

	// handle possible error returned by done
	defer func() {
		if derr := done(ctx); derr != nil {
			log.Printf("lease done error: %v", derr)
		}
	}()

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
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("error closing registry v2 response body: %v", cerr)
		}
	}()

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
	configDesc, layers, manifestBytes, mediaType, err := FetchManifest(token, "library/alpine", "latest")
	if err != nil {
		log.Println(os.Stderr, "FetchManifest error:", err)
		os.Exit(1)
	}

	fmt.Println("Config digest:", configDesc.Digest)
	fmt.Println("Layers:")
	for _, d := range layers {
		fmt.Println(" -", d.Digest)
	}

	cs := containerdClient.ContentStore()

	// Ensure layer blobs are present
	for _, entry := range layers {
		// Info expects a digest or ref
		info, err := cs.Info(ctx, entry.Digest)
		if err == nil {
			// blob exists locally
			log.Printf("Blob already present locally: %s\n  info: %+v", entry.Digest, info)
			continue
		}

		// If it's some error other than NotFound, log and continue
		if !errdefs.IsNotFound(err) {
			log.Printf("Error getting content info for %s: %v", entry.Digest, err)
			continue
		}

		// Not found -> fetch
		log.Printf("Content info for %s not found locally. Proceeding to fetch.", entry.Digest)
		if err := fetchAndStreamBlob(ctx, cs, token, "library/alpine", entry.Digest, entry.MediaType); err != nil {
			log.Printf("Error fetching and streaming blob %s: %v", entry.Digest, err)
			continue
		}
		info, err = cs.Info(ctx, entry.Digest)
		if err != nil {
			log.Printf("Fetch succeeded but Info failed for %s: %v", entry.Digest, err)
		} else {
			log.Printf("Successfully stored blob %s: size=%d created=%s updated=%s labels=%v", info.Digest, info.Size, info.CreatedAt, info.UpdatedAt, info.Labels)

		}
	}

	// Ensure config blob is present
	if configDesc.Digest == "" {
		log.Println("No config descriptor found in manifest; skipping config fetch")
	} else {
		info, err := cs.Info(ctx, configDesc.Digest)
		if err == nil {
			log.Printf("Config blob already present locally: %s\n  info: %+v", configDesc.Digest, info)
		} else if !errdefs.IsNotFound(err) {
			log.Printf("Error checking config blob %s: %v", configDesc.Digest, err)
		} else {
			log.Printf("Config %s not found locally. Fetching...", configDesc.Digest)
			cfgMT := configDesc.MediaType
			if cfgMT == "" {
				cfgMT = "application/vnd.oci.image.config.v1+json"
			}
			if err := fetchAndStreamBlob(ctx, cs, token, "library/alpine", configDesc.Digest, cfgMT); err != nil {
				log.Printf("Error fetching config blob %s: %v", configDesc.Digest, err)
			} else {
				info, _ := cs.Info(ctx, configDesc.Digest)
				log.Printf("Successfully stored config blob %s: %+v", configDesc.Digest, info)
			}
		}
	}

	// Finally write the manifest itself to the content store
	if len(manifestBytes) == 0 {
		log.Println("manifest bytes empty; skipping manifest write")
	} else {
		manifestDigest := digest.FromBytes(manifestBytes)
		ref := fmt.Sprintf("docker.io/%s@%s", "library/alpine", manifestDigest)
		log.Printf("Writing manifest blob to content store: ref=%s mediaType=%s size=%d", ref, mediaType, len(manifestBytes))

		manifestDescriptor := v1.Descriptor{
			MediaType: mediaType,
			Digest:    manifestDigest,
			Size:      int64(len(manifestBytes)),
		}
		w, err := content.OpenWriter(ctx, cs, content.WithRef(ref), content.WithDescriptor(manifestDescriptor))
		if err != nil {
			if errdefs.IsAlreadyExists(err) {
				log.Printf("Manifest %s already exists in content store; skipping", manifestDigest)
			} else {
				log.Printf("Error opening writer for manifest %s: %v", manifestDigest, err)
			}
		} else {
			defer func() {
				if cerr := w.Close(); cerr != nil {
					log.Printf("error closing manifest writer: %v", cerr)
				}
			}()
			if _, err := w.Write(manifestBytes); err != nil {
				_ = w.Close()
				cs.Abort(ctx, ref)
				log.Printf("Error writing manifest bytes: %v", err)
			} else {
				if err := w.Commit(ctx, int64(len(manifestBytes)), manifestDigest); err != nil {
					if errdefs.IsAlreadyExists(err) {
						log.Printf("Manifest %s already exists (commit)", manifestDigest)
					} else {
						log.Printf("Failed to commit manifest %s: %v", manifestDigest, err)
					}
				} else {
					log.Printf("Successfully committed manifest %s", manifestDigest)
				}
			}
		}

		err = registerImage(ctx, containerdClient, manifestDescriptor, "docker.io/library/alpine")
		if err != nil {
			log.Printf("Error registering image in containerd: %v", err)
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

	u, err := neturl.Parse(realm)
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
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("error closing token response body: %v", cerr)
		}
	}()

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

func FetchManifest(token, imageName, tag string) (config Descriptor, layerDescs []Descriptor, manifestBytes []byte, mediaType string, err error) {
	accept := strings.Join([]string{
		mediaManifestList,
		mediaOCIIndex,
		mediaManifestV2,
		mediaOCIManifest,
	}, ", ")

	// helper to GET a manifest (by ref or digest) and return body + content-type
	get := func(ref string) (body []byte, contentType string, err error) {
		manifestURL := "https://" + defaultUrl + "/v2/" + imageName + "/manifests/" + ref
		req, err := http.NewRequest("GET", manifestURL, nil)
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
		defer func() {
			if cerr := resp.Body.Close(); cerr != nil {
				log.Printf("error closing manifest response body: %v", cerr)
			}
		}()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			return nil, "", fmt.Errorf("manifest request failed: %s %s", resp.Status, strings.TrimSpace(string(b)))
		}
		ct := resp.Header.Get("Content-Type")
		b, err := io.ReadAll(resp.Body)
		return b, ct, err
	}

	b, ct, err := get(tag)
	if err != nil {
		return Descriptor{}, nil, nil, "", err
	}
	ct = strings.ToLower(ct)

	if strings.Contains(ct, "manifest.list") || strings.Contains(ct, "index") {
		var idx Index
		if err := json.Unmarshal(b, &idx); err != nil {
			return Descriptor{}, nil, nil, "", fmt.Errorf("failed to decode index: %w", err)
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
			return Descriptor{}, nil, nil, "", fmt.Errorf("no matching manifest for platform %s/%s", targetOS, targetArch)
		}

		log.Printf("Selected manifest from index: digest=%s mediaType=%s", chosen.Digest, chosen.MediaType)

		b, ct, err = get(string(chosen.Digest))
		if err != nil {
			return Descriptor{}, nil, nil, "", err
		}
	}

	// Parse manifest (single image manifest)
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return Descriptor{}, nil, nil, "", fmt.Errorf("failed to decode manifest: %w", err)
	}

	if m.Config.Digest == "" {
		return Descriptor{}, nil, nil, "", fmt.Errorf("manifest has no config digest")
	}

	config = m.Config
	layerDescs = make([]Descriptor, 0, len(m.Layers))
	for _, l := range m.Layers {
		if l.Digest != "" {
			layerDescs = append(layerDescs, l)
		}
	}
	manifestBytes = b
	mediaType = strings.ToLower(ct)
	return config, layerDescs, manifestBytes, mediaType, nil
}

// progressReader wraps a reader and logs progress periodically.
type progressReader struct {
	r     io.Reader
	dgst  digest.Digest
	total int64
	last  time.Time
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		atomic.AddInt64(&p.total, int64(n))
	}
	if time.Since(p.last) > 2*time.Second {
		p.last = time.Now()
		log.Printf("downloading %s: %d bytes transferred", p.dgst, atomic.LoadInt64(&p.total))
	}
	return n, err
}

// Call this from the loop where you currently have the TODO.
// imageName should be the repository name (e.g. "library/alpine").
func fetchAndStreamBlob(ctx context.Context, cs content.Store, token, imageName string, dgst digest.Digest, mediaType string) error {
	blobUrl := "https://" + defaultUrl + "/v2/" + imageName + "/blobs/" + dgst.String()
	log.Printf("fetchAndStreamBlob: GET %s (image=%s digest=%s)", blobUrl, imageName, dgst)
	req, err := http.NewRequest("GET", blobUrl, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		log.Println("Authorization: (present)")
	} else {
		log.Println("Authorization: (absent)")
	}
	// optional: request chunked transfer or any particular Accept if needed
	req.Header.Set("Accept", "*/*")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			log.Printf("error closing blob response body: %v", cerr)
		}
	}()

	log.Printf("blob response status: %s", resp.Status)
	for k, v := range resp.Header {
		log.Printf("response header: %s=%s", k, strings.Join(v, ","))
	}

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("blob GET %s: %s %s", dgst.String(), resp.Status, strings.TrimSpace(string(b)))
	}

	ref := fmt.Sprintf("docker.io/%s@%s", imageName, dgst.String())
	contentLength := resp.Header.Get("Content-Length")
	var expectedSize int64
	if contentLength == "" {
		log.Printf("Content-Length header absent for %s: will use actual bytes written", dgst)
		expectedSize = 0
	} else {
		expectedSize, err = strconv.ParseInt(contentLength, 10, 64)
		if err != nil {
			log.Printf("warning: error parsing content length '%s' for %s: %v; will use actual bytes written", contentLength, dgst, err)
			expectedSize = 0
		}
	}

	// wrap body with progress reader to provide periodic updates
	pr := &progressReader{r: resp.Body, dgst: dgst}

	writer, err := content.OpenWriter(ctx, cs, content.WithRef(ref), content.WithDescriptor(v1.Descriptor{
		MediaType: mediaType,
		Digest:    dgst,
		Size:      expectedSize,
	}))

	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			log.Printf("Blob %s already exists in content store (ref=%s); skipping download", dgst, ref)
			return nil
		}
		log.Printf("Warning: error opening blob %s: %v", dgst, err)
		return err
	}

	defer func() {
		if cerr := writer.Close(); cerr != nil {
			log.Printf("error closing writer for %s: %v", dgst, cerr)
		}
	}()

	n, err := io.Copy(writer, pr)
	if err != nil {
		_ = writer.Close()
		cs.Abort(ctx, ref)
		return fmt.Errorf("failed to copy data for %s: %w", dgst, err)
	}

	if err := writer.Commit(ctx, n, dgst, content.WithLabels(map[string]string{
		"containerd.io/gc.ref.content.0": dgst.String(),
	})); err != nil {
		if errdefs.IsAlreadyExists(err) {
			log.Printf("Content %s already exists (caught during Commit)", dgst)
			return nil
		}
		return fmt.Errorf("failed to commit %s: %w", dgst, err)
	}
	log.Printf("Successfully committed blob %s to content store", dgst)
	return nil
}

func registerImage(
	ctx context.Context,
	client *containerd.Client,
	manifestDesc v1.Descriptor,
	imageName string) error {
	img := images.Image{
		Name:   imageName,
		Target: manifestDesc,
	}

	_, err := client.ImageService().Create(ctx, img)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			log.Printf("Image %s already registered in containerd", imageName)
			_, err := client.ImageService().Update(ctx, img)
			return err
		}
	}
	return nil
}
