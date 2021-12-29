// Package dumper is a debugging tool for the workloadmeta store.  If enabled,
// it simply subscribes to all events from the store and logs them.  Each log
// entry includes the string "WLM" for ease of grepping.
package dumper

import (
	"fmt"
	"strings"

	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

// Enable enables dumping workloadmeta events.
//
// To use this, temporarily add `dumper.Enable()` to `LoadComponents`in
// `cmd/agent/common/loader.go`.
//
// If no reference to this package exists, then the package will not be
// compiled into the built agent and will not add binary size.
func Enable() {
	ch := workloadmeta.GetGlobalStore().Subscribe("dumper", nil)

	go dumpFrom(ch)
}

func dumpFrom(ch chan workloadmeta.EventBundle) {
	log.Debug("WLM dumper enabled")
	bundleCount := 0
	for {
		eventBundle, ok := <-ch
		if !ok {
			break
		}
		close(eventBundle.Ch)

		for i, evt := range eventBundle.Events {
			prefix := fmt.Sprintf("WLM %d/%d", bundleCount, i)
			dumpEvent(prefix, evt)
		}
		bundleCount++
	}
}

func dumpEvent(prefix string, evt workloadmeta.Event) {
	sources := make([]string, len(evt.Sources))
	for i, src := range evt.Sources {
		sources[i] = string(src)
	}
	typ := "set"
	if evt.Type == workloadmeta.EventTypeUnset {
		typ = "unset"
	}
	log.Debugf("%s: %s %s, Sources=[%s]", prefix, typ, evt.Entity.GetID(), strings.Join(sources, ", "))
	s := evt.Entity.String(true)
	for _, l := range strings.Split(s, "\n") {
		if len(l) > 0 {
			log.Debugf("%s: Entity: %s", prefix, l)
		}
	}
}
