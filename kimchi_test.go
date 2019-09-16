// kimchi_test.go - Katzenpost self contained test network.
// Copyright (C) 2017  Yawning Angel, David Stainton, Masala.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package kimchi_test
import (
	ki "github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

const basePort = 42000

// TestGetClientConfig tests that a client configuration can be generated correctly
func TestGetClientConfig(t *testing.T) {
	require := require.New(t)
	nVoting := 3
	nProvider := 2
	nMix := 6
	for _, v := range([]bool{true, false}) {
		k := ki.NewKimchi(basePort+50, "", nil, v, nVoting, nProvider, nMix)
		t.Logf("Launching nonvoting authority and calling GetClientConfig()")
		k.Run()

		go func() {
			defer k.Shutdown()
			cfg, username, privkey, err := k.GetClientConfig()
			t.Logf("c: %v u: %v k: %v", cfg, username, privkey)
			require.Nil(err)

			if err != nil {
				panic(err)
			}
			t.Logf("Received shutdown request.")
			t.Logf("All servers halted.")
		}()

		k.Wait()
		t.Logf("Terminated.")
	}

}

// TestRunNonvoting tests Kimchi.Run with a nonvoting directory authority configuration
func TestRunNonvoting(t *testing.T) {
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort+50, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Nonvoting mixnet.")
	k.Run()
	<-time.After(60 * time.Second) // run for a short duration. See authority repository for other tests
	k.Shutdown()
	t.Logf("Received shutdown request.")
	k.Wait()
	t.Logf("All servers halted.")
	t.Logf("Terminated.")
}

// TestNewKimchi tests NewKimchi()
func TestNewKimchi(t *testing.T) {
	voting := false
	require := require.New(t)
	nVoting := 0
	nProvider := 2
	nMix := 6
	// Voting
	k := ki.NewKimchi(basePort+50, "", nil, voting, nVoting, nProvider, nMix)
	require.NotNil(k)

	// Nonvoting
	k = ki.NewKimchi(basePort+100, "", nil, !voting, 0, nProvider, nMix)
	require.NotNil(k)
}

// TestRunVoting tests Kimchi.Run with a voting directory authority configuration
func TestRunVoting(t *testing.T) {
	require := require.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort+100, "", nil, voting, nVoting, nProvider, nMix)
	require.NotNil(k)
	t.Logf("Running Voting mixnet.")
	k.Run()
	<-time.After(60 * time.Second) // run for a short duration. See authority repository for other tests
	k.Shutdown()
	t.Logf("Received shutdown request.")
	k.Wait()
	t.Logf("All servers halted.")
	t.Logf("Terminated.")
}
