package kimchi

import (
	"context"
	"testing"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/stretchr/testify/require"
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

func TestBootstrapVoting(t *testing.T) {
	require := require.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort, "",  voting, nVoting, nProvider, nMix)
	k.Run()
	t.Logf("Running mixnet.")

	go func() {
		<-time.After(3 * time.Minute)
		// verify that consensus was made
		p, err := k.pkiClient()
		require.NoError(err)
		epoch, _, _ := epochtime.Now()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
		defer cancel()
		_, _, err = p.Get(ctx, epoch)
		require.NoError(err)
		t.Logf("Received shutdown request.")
		k.Shutdown()
		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}
