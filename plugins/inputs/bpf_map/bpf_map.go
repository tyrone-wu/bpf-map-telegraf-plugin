package bpf_map

import (
	_ "embed"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

var sampleConfig string = ``

type BpfMap struct {
	KeySize    bool `toml:"key_size"`
	ValueSize  bool `toml:"value_size"`
	MaxEntries bool `toml:"max_entries"`
	MapFlags   bool `toml:"map_flags"`

	Log telegraf.Logger `toml:"-"`
}

func (*BpfMap) SampleConfig() string {
	return sampleConfig
}

func (m *BpfMap) Gather(acc telegraf.Accumulator) error {
	// Iterate over bpf maps loaded on the host
	prev := ebpf.MapID(0)
	for {
		map_id, err := ebpf.MapGetNextID(prev)
		// Exit when finish iterating over all maps
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			prev = map_id
			continue
		}

		map_info, err := ebpf.NewMapFromID(map_id)
		if err != nil {
			prev = map_id
			continue
		}

		info, err := map_info.Info()
		if err != nil {
			prev = map_id
			continue
		}
		now := time.Now()

		// Fields
		fields := map[string]interface{}{}
		if m.KeySize {
			fields["key_size"] = info.KeySize
		}
		if m.ValueSize {
			fields["value_size"] = info.ValueSize
		}
		if m.MaxEntries {
			fields["max_entries"] = info.MaxEntries
		}
		if m.MapFlags {
			fields["map_flags"] = info.Flags
		}

		// Tags
		tags := map[string]string{
			"id":   strconv.FormatUint(uint64(map_id), 10),
			"type": info.Type.String(),
			"name": info.Name,
		}

		acc.AddFields("bpf_map", fields, tags, now)
		prev = map_id
	}

	return nil
}

func (m *BpfMap) Init() error {
	return nil
}

func init() {
	inputs.Add("bpf_map", func() telegraf.Input {
		return &BpfMap{
			MaxEntries: true,
		}
	})
}
