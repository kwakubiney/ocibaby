# ocibaby
minimal container runtime + registry client

## Disclaimer

**This tool currently supports Docker Hub only.** Custom, private, or alternative registries are not supported.

## Prerequisites

- **OS**: Linux only (requires containerd runtime)
- **containerd**: Must be installed and running with socket at `/run/containerd/containerd.sock`

## Usage

```bash
ocibaby -image=library/alpine
```

### Flags
- `-image` - Image name, required (e.g., `library/alpine`)
- `-tag` - Image tag (default: `latest`)
