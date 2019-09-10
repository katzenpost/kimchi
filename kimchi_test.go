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
	"testing"
)

const basePort = 42000

// TestBootstrapNonvoting tests that the nonvoting authority bootstraps and provides a consensus document
func TestBootstrapNonvoting(t *testing.T) {
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := ki.NewKimchi(basePort+50, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running Bootstrap Nonvoting mixnet.")
	k.Run()

	go func() {
		defer k.Shutdown()
		t.Logf("Received shutdown request.")
		t.Logf("All servers halted.")
	}()

	k.Wait()
	t.Logf("Terminated.")
}


