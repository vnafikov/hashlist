# Hash List

Generates a checksum manifest for a directory tree to verify file integrity.

### Usage:
Create a checksum manifest:
```bash
hashlist [-alg=<algorithm: sha256, blake3>] [-reconcile=<path to source manifest>] <path>
```

Extract a checksum manifest for a path:
```bash
hashlist -extract=<path> <path to source manifest>
```

### Help:
```bash
hashlist -h
```
