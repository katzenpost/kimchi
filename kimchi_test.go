package kimchi

import (
	"context"
	"testing"
	"time"

	aServer "github.com/katzenpost/authority/voting/server"
	"github.com/katzenpost/core/crypto/cert"
	cClient "github.com/katzenpost/client"
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
		_, _, till := epochtime.Now()
		<-time.After(till)

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
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
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
		<-time.After(5 * time.Second)
		t.Logf("Killing an Authority")
		if !assert.True(k.killAnAuth()) {
			return
		}
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
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

	go func() {
		defer k.Shutdown()
		// align with start of epoch
		startEpoch, _, till := epochtime.Now()
		<-time.After(till)
		for i:= startEpoch+1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for the current epoch
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

func TestAuthorityJoinConsensus(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	nRounds := uint64(3)
	k := NewKimchi(basePort+400, "", voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	delay := epochtime.Period // miss the first voting round
	k.runWithDelayedAuthority(delay)
	go func() {
		defer k.Shutdown()
		// align with start of epoch
		startEpoch, _, till := epochtime.Now()
		<-time.After(till)
		for i := startEpoch + 1; i < startEpoch+nRounds; i++ {
			_, _, till = epochtime.Now()
			// wait until end of epoch
			<-time.After(till)
			t.Logf("Time is up!")

			// verify that consensus was made for the current epoch
			p, err := k.pkiClient()
			if assert.NoError(err) {
				epoch, _, _ := epochtime.Now()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				c, r, err := p.Get(ctx, epoch)
				if assert.NoError(err) {
					t.Logf("Got a consensus: %v", c)
					s, err := cert.GetSignatures(r)
					if assert.NoError(err) {
						// Confirm full consensus was made in final round
						if i == startEpoch+nRounds-1 {
							if assert.Equal(nVoting, len(s)) {
								t.Logf("%d Signatures found on consensus as expected", nVoting)
							} else {
								t.Logf("Found %d signatures, expected %d", len(s), nVoting)
							}
						}
					}
				}
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}

func TestClientConnect(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := NewKimchi(basePort+500, "",  voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")

		// create a client configuration
		cfg, err := k.getClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := cClient.New(cfg)
		assert.NoError(err)

		// instantiate a session
		s, err := c.NewSession()
		assert.NoError(err)

		// get a PKI document? needs client method...
		desc, err := s.GetService("loop") // XXX: returns nil and no error?!
		assert.NoError(err)

		// send a message
		t.Logf("desc.Provider: %s", desc.Provider)
		surb, err := s.SendUnreliableQuery(desc.Name, desc.Provider, []byte("hello!"))
		assert.NoError(err)

		// block and wait for a reply
		r := s.WaitForReply(surb)
		t.Logf("Got reply: %s", r)
	}()

	k.Wait()
	t.Logf("Terminated.")
}
