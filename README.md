# `bpf-map-info` Input Plugin

Collects metadata information on BPF maps loaded on the host.

## Configuration

```conf
# Fetch metadata metrics from BPF maps on the host.
[[inputs.bpf_map]]
  ## Optional Fields

  ## Size of map key in bytes.
  ##
  ## Corresponds to `key_size` field in `bpf_map_info`.
  key_size = true

  ## Size of map value in bytes.
  ##
  ## Corresponds to `value_size` field in `bpf_map_info`.
  value_size = true

  ## Max entries map can hold.
  ##
  ## Corresponds to `max_entries` field in `bpf_map_info`.
  max_entries = true

  ## Map flags used in loading.
  ##
  ## Corresponds to `map_flags` field in `bpf_map_info`.
  map_flags = true
```

## Metrics

These metrics are extracted from the `bpf_map_info` object.

- bpf_map
  - tags:
    - id
    - type
    - name
  - fields:
    - key_size (integer, bytes)
    - value_size (integer, bytes)
    - max_entries (integer, count)
    - map_flags (integer)

## Usage

Build binary:

```golang
go build -o bpf-map cmd/main.go
```

Execute binary:

```golang
sudo ./bpf-map -config plugin.conf
```
