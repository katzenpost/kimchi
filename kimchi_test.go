package kimchi

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
	//"github.com/stretchr/testify/assert"
)

func TestBootstrapNonvoting(t *testing.T) {
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort, "",  voting, nVoting, nProvider, nMix)
	k.Run()

	// Wait for a signal to tear it all down.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	t.Logf("Running mixnet.")
	go func() {
		<-time.After(1 * time.Minute)
		t.Logf("Received shutdown request.")
		for _, svr := range k.servers {
			svr.Shutdown()
		}
		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}
