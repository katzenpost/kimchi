// kimchi.go - Katzenpost self contained test network.
// Copyright (C) 2017  Yawning Angel, David Stainton.
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

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	//"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/kimchi"
	//"github.com/katzenpost/core/crypto/rand"
)

func main() {
	var voting = flag.Bool("voting", false, "use voting authorities")
	var nVoting = flag.Int("nv", 3, "the number of voting authorities")
	var nProvider = flag.Int("np", 2, "the number of providers")
	var nMix = flag.Int("nm", 6, "the number of mixes")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var memprofile = flag.String("memprofile", "", "write memory profile to this file")

	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	k := kimchi.NewKimchi(30000, "",  *voting, *nVoting, *nProvider, *nMix)

	k.Run()

	/*
	// Generate the private keys used by the clients in advance so they
	// can know each other.
	alicePrivateKey, _ := ecdh.NewKeypair(rand.Reader)
	bobPrivateKey, _ := ecdh.NewKeypair(rand.Reader)
	k.AddRecipient("alice@provider-0.example.org", alicePrivateKey.PublicKey())
	k.AddRecipient("bob@provider-1.example.org", bobPrivateKey.PublicKey())

	// Initialize Alice's mailproxy.
	// XXX aliceProvider := s.authProviders[0].Identifier
	if err = k.thwackUser(k.nodeConfigs[0], "aLiCe", alicePrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	// Initialize Bob's mailproxy.
	// XXX bobProvider := s.authProviders[1].Identifier
	if err = k.thwackUser(k.nodeConfigs[1], "BoB", bobPrivateKey.PublicKey()); err != nil {
		log.Fatalf("Failed to add user: %v", err)
	}
	*/

	// Wait for a signal to tear it all down.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	<-ch
	log.Printf("Received shutdown request.")
	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
	}

	k.Shutdown()
	log.Printf("All servers halted.")

	// Wait for the log tailers to return.  This typically won't re-log the
	// shutdown sequence, but if people need the logs from that, they will
	// be in each `DataDir` as needed.
	k.Wait()
	log.Printf("Terminated.")
}
