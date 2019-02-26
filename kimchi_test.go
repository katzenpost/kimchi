package kimchi

import (
	"context"
	"testing"
	"time"

	aServer "github.com/katzenpost/authority/voting/server"
	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/epochtime"
	"github.com/stretchr/testify/assert"
)

// Shutdown an authority
func (k *kimchi) killAnAuth() bool {
	for _, svr := range k.servers {
		switch svr.(type) {
		case *aServer.Server:
			svr.Shutdown()
			return true
		}
	}
	return false
}

func TestBootstrapNonvoting(t *testing.T) {
	assert := assert.New(t)
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort+50, "",  voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Nonvoting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		<-time.After(1 * time.Minute)
		t.Logf("Received shutdown request.")
		p, err := k.pkiClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			c, _, err := p.Get(ctx, epoch)
			assert.NoError(err)
			t.Logf("Got a consensus: %v", c)
		}

		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}

func TestBootstrapVoting(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort+100, "",  voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Voting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		<-time.After(3 * time.Minute)
		t.Logf("Time is up!")
		// verify that consensus was made
		p, err := k.pkiClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			c, _, err := p.Get(ctx, epoch)
			if assert.NoError(err) {
				t.Logf("Got a consensus: %v", c)
			} else {
				t.Logf("Consensus failed")
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

func TestBootstrapVotingThreshold(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort, "",  voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Voting mixnet.")
	k.Run()

	// start a goroutine that kills one authority and verifies that
	// consensus is reached with the remaining authorities
	go func() {
		defer k.Shutdown()
		// Varying this delay will set where in the
		// voting protocol the authority fails.
		<-time.After(30 * time.Second)
		t.Logf("Killing an Authority")
		if !assert.True(k.killAnAuth()) {
			return
		}
		<-time.After(100 * time.Second)
		t.Logf("Time is up!")
		// verify that consensus was made
		p, err := k.pkiClient()
		if assert.NoError(err) {
			epoch, _, _ := epochtime.Now()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			t.Logf("Fetching a consensus")
			c, r, err := p.Get(ctx, epoch)
			if assert.NoError(err) {
				t.Logf("Got a consensus: %v", c)
				s, err := cert.GetSignatures(r)
				if assert.NoError(err) {
					// Confirm exactly 2 signatures are present.
					if assert.Equal(2, len(s)) {
						t.Logf("2 Signatures found on consensus as expected")
					} else {
						t.Logf("Found %d signatures, expected 2", len(s))
					}
				}
			}
		}
	}()


	k.Wait()
	t.Logf("Terminated.")
}

func TestMultipleVotingRounds(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	nRounds := uint64(3)
	k := NewKimchi(basePort+300, "",  voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	k.Run()

	startEpoch, _, till := epochtime.Now()
	go func() {
		defer k.Shutdown()
		// align with start of epoch
		<-time.After(till)
		for i:= startEpoch+1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for the next epoch
			p, err := k.pkiClient()
			if assert.NoError(err) {
				epoch, _, _ := epochtime.Now()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				c, _, err := p.Get(ctx, epoch)
				if assert.NoError(err) {
					t.Logf("Got a consensus: %v", c)
				} else {
					t.Logf("Consensus failed")
				}
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}
