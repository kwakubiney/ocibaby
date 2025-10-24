# ocibaby
minimal container runtime + registry client

## Usage

```bash
# Pull and run an image
ocibaby -image=library/alpine

# Run from custom registry
ocibaby -registry=quay.io -image=bitnami/nginx -tag=latest
```

### Flags
- `-registry` - Docker registry URL (default: `registry-1.docker.io`)
- `-image` - Image name, required (e.g., `library/alpine`)
- `-tag` - Image tag (default: `latest`)
