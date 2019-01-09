package kimchi

import (
	"testing"
	"time"
)

func TestBootstrapNonvoting(t *testing.T) {
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort, "",  voting, nVoting, nProvider, nMix)
	k.Run()
	t.Logf("Running mixnet.")

	go func() {
		<-time.After(1 * time.Minute)
		t.Logf("Received shutdown request.")
		k.Shutdown()
		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}
