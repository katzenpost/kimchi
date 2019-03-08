package kimchi

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	aServer "github.com/katzenpost/authority/voting/server"
	cClient "github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/epochtime"
	sServer "github.com/katzenpost/server"
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

// Shutdown a mix
func (k *kimchi) killAMix() bool {
	for _, svr := range k.servers {
		switch svr.(type) {
		case *sServer.Server:
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
	k := NewKimchi(basePort+50, "", voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Nonvoting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		<-time.After(till + epochtime.Period)

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
	k := NewKimchi(basePort+100, "", voting, nVoting, nProvider, nMix)
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
	k := NewKimchi(basePort, "", voting, nVoting, nProvider, nMix)
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
			r, err := retry(p, epoch, 3)
			assert.NoError(err)
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
	k := NewKimchi(basePort+300, "", voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	k.Run()

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

			// verify that consensus was made for each epoch
			p, err := k.pkiClient()
			assert.NoError(err)
			epoch, _, _ := epochtime.Now()
			r, err := retry(p, epoch, 3)
			assert.NoError(err)
			s, err := cert.GetSignatures(r)
			assert.NoError(err)

			// check that we obtained a fully signed consensus in the final round
			if i == startEpoch+nRounds-1 {
				if assert.Equal(nVoting, len(s)) {
					t.Logf("%d Signatures found on consensus as expected", nVoting)
				} else {
					t.Logf("Found %d signatures, expected %d", len(s), nVoting)
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
	k := NewKimchi(basePort+500, "", voting, nVoting, nProvider, nMix)
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

		// add client log output
		go k.logTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

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

		// wait until timeout or a reply is received
		ch := make(chan []byte)
		go func() {
			ch <-s.WaitForReply(surb)
		}()
		select {
		case <-time.After(1 * time.Minute):
			assert.Fail("Timed out, no reply received")
		case r := <-ch:
			t.Logf("Got reply: %s", r)
		}
		close(ch)
		c.Shutdown()
		c.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

func TestClientReceiveMessage(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 3
	k := NewKimchi(basePort+600, "", voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		// XXX; there seems to be a bug w/ messages getting dropped @ epoch transition
		till += epochtime.Period + 10*time.Second // wait for one vote round, aligned at start of epoch + slop
		<-time.After(till)
		t.Logf("Time is up!")

		// create a client configuration
		cfg, err := k.getClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := cClient.New(cfg)
		assert.NoError(err)
		assert.NotNil(c)

		// add client log output
		go k.logTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

		// instantiate a session
		s, err := c.NewSession()
		assert.NoError(err)

		// send a message
		surb, err := s.SendUnreliableQuery(cfg.Account.User, cfg.Account.Provider, []byte("hello!"))
		assert.NoError(err)

		// wait until timeout or a reply is received
		ch := make(chan []byte)
		go func() {
			ch <-s.WaitForReply(surb)
		}()
		select {
		case <-time.After(1 * time.Minute):
			assert.Fail("Timed out, no reply received")
		case r := <-ch:
			t.Logf("Got reply: %s", r)
		}
		close(ch)
		c.Shutdown()
		c.Wait()
	}()
	k.Wait()
	t.Logf("Terminated.")
}

func TestTopologyChange(t *testing.T) {
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 3
	nRounds := uint64(5)
	k := NewKimchi(basePort+300, "", voting, nVoting, nProvider, nMix)
	t.Logf("Running Voting mixnet for %d rounds.", nRounds)
	k.Run()

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
				c, _, err := p.Get(ctx, epoch)
				if assert.NoError(err) {
					t.Logf("Got a consensus: %v", c)
				} else {
					t.Logf("Consensus failed")
				}
			}

			// kill 1 mix and verify topology rebalances uniformly
			if i == startEpoch+2 {
				assert.True(k.killAMix())
			}
		}
	}()

	k.Wait()
	t.Logf("Terminated.")
}
