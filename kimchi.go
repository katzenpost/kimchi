// kimchi.go - Katzenpost self contained test network.
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

package kimchi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/textproto"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sync"
	"time"

	"github.com/hpcloud/tail"
	nvClient "github.com/katzenpost/authority/nonvoting/client"
	aServer "github.com/katzenpost/authority/nonvoting/server"
	aConfig "github.com/katzenpost/authority/nonvoting/server/config"
	vClient "github.com/katzenpost/authority/voting/client"
	vServer "github.com/katzenpost/authority/voting/server"
	vConfig "github.com/katzenpost/authority/voting/server/config"
	csConfig "github.com/katzenpost/catshadow/config"
	cConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	klog "github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/thwack"
	nServer "github.com/katzenpost/server"
	sServer "github.com/katzenpost/server"
	sConfig "github.com/katzenpost/server/config"
)

const (
	logFile = "kimchi.log"
)

var tailConfig = tail.Config{
	Poll:   true,
	Follow: true,
	Logger: tail.DiscardingLogger,
}

type Kimchi struct {
	sync.Mutex
	sync.WaitGroup

	baseDir   string
	logWriter io.Writer

	authConfig        *aConfig.Config
	votingAuthConfigs []*vConfig.Config
	authIdentity      *eddsa.PrivateKey
	voting            bool
	parameters        *Parameters
	nVoting           int
	nProvider         int
	nMix              int

	nodeConfigs []*sConfig.Config
	lastPort    uint16
	authPort    uint16
	nodeIdx     int
	providerIdx int

	recipients map[string]*ecdh.PublicKey

	servers []server
	tails   []*tail.Tail
}

type server interface {
	Shutdown()
	Wait()
}

type Parameters struct {
	vConfig.Parameters
}

// NewKimchi returns an initialized kimchi
func NewKimchi(basePort int, baseDir string, parameters *Parameters, voting bool, nVoting, nProvider, nMix int) *Kimchi {
	if parameters == nil {
		parameters = &Parameters{}
	}
	k := &Kimchi{
		lastPort:    uint16(basePort),
		authPort:    uint16(basePort),
		recipients:  make(map[string]*ecdh.PublicKey),
		nodeConfigs: make([]*sConfig.Config, 0),
		voting:      voting,
		nVoting:     nVoting,
		nProvider:   nProvider,
		nMix:        nMix,
		parameters:  parameters,
	}
	// Create the base directory and bring logging online.
	var err error
	if baseDir == "" {
		k.baseDir, err = ioutil.TempDir("", "kimchi")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create base directory: %v\n", err)
			os.Exit(-1)
		}
	} else {
		k.baseDir = baseDir
	}
	if err = k.initLogging(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logging: %v\n", err)
		os.Exit(-1)
	}
	if err = k.initConfig(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initConfig(): %v", err)
		return nil
	}
	return k
}

func (k *Kimchi) Run() {
	// Launch all the nodes.
	for _, v := range k.nodeConfigs {
		v.FixupAndValidate()
		svr, err := nServer.New(v)
		if err != nil {
			log.Fatalf("Failed to launch node: %v", err)
		}

		k.servers = append(k.servers, svr)
		go k.LogTailer(v.Server.Identifier, filepath.Join(v.Server.DataDir, v.Logging.File))

		// Add LogTailers for cbor plugins
		if v.Server.IsProvider {
			for _, plugin := range v.Provider.CBORPluginKaetzchen {
				switch plugin.Capability {
				case "spool", "panda":
					if log_dir, ok := plugin.Config["log_dir"]; ok {
						if matches, err := filepath.Glob(filepath.Join(log_dir.(string), plugin.Capability + ".*.log")); err == nil {
							if len(matches) == 1 {
								go k.LogTailer(v.Server.Identifier, matches[0])
							}
						}
					}
				}
			}
		}
	}
	k.runAuthority()
}

func (k *Kimchi) initConfig() error {
	// Generate the authority configs
	var err error
	if k.voting {
		err = k.genVotingAuthoritiesCfg()
		if err != nil {
			log.Fatalf("getVotingAuthoritiesCfg failed: %s", err)
		}
	} else {
		if err = k.genAuthConfig(); err != nil {
			log.Fatalf("Failed to generate authority config: %v", err)
		}
	}

	// Generate the provider configs.
	for i := 0; i < k.nProvider; i++ {
		if err = k.genNodeConfig(true, k.voting); err != nil {
			log.Fatalf("Failed to generate provider config: %v", err)
		}
	}

	// Generate the node configs.
	for i := 0; i < k.nMix; i++ {
		if err = k.genNodeConfig(false, k.voting); err != nil {
			log.Fatalf("Failed to generate node config: %v", err)
		}
	}

	// Generate the node lists.
	if k.voting {
		providerWhitelist, mixWhitelist, err := k.generateVotingWhitelist()
		if err != nil {
			panic(err)
		}
		for _, aCfg := range k.votingAuthConfigs {
			aCfg.Mixes = mixWhitelist
			aCfg.Providers = providerWhitelist
		}
	} else {
		if providers, mixes, err := k.generateWhitelist(); err == nil {
			k.authConfig.Mixes = mixes
			k.authConfig.Providers = providers
		} else {
			log.Fatalf("Failed to generateWhitelist with %s", err)
		}
	}
	return err
}

func (k *Kimchi) runAuthority() {
	var err error
	if k.voting {
		err = k.runVotingAuthorities()
	} else {
		err = k.runNonvoting()
	}
	if err != nil {
		panic(err)
	}
}

// Shutdown an authority
func (k *Kimchi) KillAnAuth() bool {
	for _, svr := range k.servers {
		switch svr.(type) {
		case *vServer.Server:
			svr.Shutdown()
			return true
		}
	}
	return false
}

// Shutdown a mix
func (k *Kimchi) KillAMix() bool {
	for _, svr := range k.servers {
		switch svr.(type) {
		case *sServer.Server:
			svr.Shutdown()
			return true
		}
	}
	return false
}

func (k *Kimchi) PKIClient() (pki.Client, error) {
	b, err := klog.New("", "DEBUG", false)
	if err != nil {
		return nil, err
	}
	if k.voting {
		p, err := sConfig.AuthorityPeersFromPeers(k.votingPeers())
		if err != nil {
			return nil, err
		}
		cfg := vClient.Config{LogBackend: b, Authorities: p}
		return vClient.New(&cfg)
	}
	cfg := nvClient.Config{LogBackend: b, Address: k.authConfig.Authority.Addresses[0], PublicKey: k.authConfig.Debug.IdentityKey.PublicKey()}
	return nvClient.New(&cfg)
}

func (k *Kimchi) initLogging() error {
	logFilePath := filepath.Join(k.baseDir, logFile)
	f, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}

	// Log to both stdout *and* the log file.
	k.logWriter = io.MultiWriter(f, os.Stdout)
	log.SetOutput(k.logWriter)

	return nil
}

func (k *Kimchi) genVotingAuthoritiesCfg() error {
	// create voting config.Parameters from generic parameters
	parameters := &vConfig.Parameters{
		SendRatePerMinute: k.parameters.SendRatePerMinute,
		Mu:                k.parameters.Mu,
		MuMaxDelay:        k.parameters.MuMaxDelay,
		LambdaP:           k.parameters.LambdaP,
		LambdaPMaxDelay:   k.parameters.LambdaPMaxDelay,
		LambdaL:           k.parameters.LambdaL,
		LambdaLMaxDelay:   k.parameters.LambdaLMaxDelay,
	}
	configs := []*vConfig.Config{}

	// initial generation of key material for each authority
	peersMap := make(map[[eddsa.PublicKeySize]byte]*vConfig.AuthorityPeer)
	for i := 0; i < k.nVoting; i++ {
		cfg := new(vConfig.Config)
		cfg.Logging = &vConfig.Logging{
			Disable: false,
			File:    "katzenpost.log",
			Level:   "DEBUG",
		}
		cfg.Parameters = parameters
		cfg.Authority = &vConfig.Authority{
			Identifier: fmt.Sprintf("authority-%v.example.org", i),
			Addresses:  []string{fmt.Sprintf("127.0.0.1:%d", k.lastPort)},
			DataDir:    filepath.Join(k.baseDir, fmt.Sprintf("authority%d", i)),
		}
		k.lastPort++
		if err := os.Mkdir(cfg.Authority.DataDir, 0700); err != nil {
			return err
		}
		idKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}

		if err != nil {
			return err
		}
		cfg.Debug = &vConfig.Debug{
			IdentityKey:      idKey,
			LinkKey:          idKey.ToECDH(),
			Layers:           3,
			MinNodesPerLayer: 1,
			GenerateOnly:     false,
		}
		configs = append(configs, cfg)
		authorityPeer := &vConfig.AuthorityPeer{
			IdentityPublicKey: cfg.Debug.IdentityKey.PublicKey(),
			LinkPublicKey:     cfg.Debug.LinkKey.PublicKey(),
			Addresses:         cfg.Authority.Addresses,
		}
		peersMap[cfg.Debug.IdentityKey.PublicKey().ByteArray()] = authorityPeer
	}

	// tell each authority about it's peers
	for i := 0; i < k.nVoting; i++ {
		peers := []*vConfig.AuthorityPeer{}
		for id, peer := range peersMap {
			if !bytes.Equal(id[:], configs[i].Debug.IdentityKey.PublicKey().Bytes()) {
				peers = append(peers, peer)
			}
		}
		configs[i].Authorities = peers
	}
	k.votingAuthConfigs = configs
	return nil
}

func (k *Kimchi) votingPeers() []*sConfig.Peer {
	peers := []*sConfig.Peer{}
	for _, peer := range k.votingAuthConfigs {
		idKey, err := peer.Debug.IdentityKey.PublicKey().MarshalText()
		if err != nil {
			continue
		}
		linkKey, err := peer.Debug.LinkKey.PublicKey().MarshalText()
		if err != nil {
			continue
		}
		p := &sConfig.Peer{
			Addresses:         peer.Authority.Addresses,
			IdentityPublicKey: string(idKey),
			LinkPublicKey:     string(linkKey),
		}
		if len(peer.Authority.Addresses) == 0 {
			continue
		}
		peers = append(peers, p)
	}
	return peers
}

func (k *Kimchi) genNodeConfig(isProvider bool, isVoting bool) error {
	const serverLogFile = "katzenpost.log"

	n := fmt.Sprintf("node-%d", k.nodeIdx)
	if isProvider {
		n = fmt.Sprintf("provider-%d", k.providerIdx)
	}
	cfg := new(sConfig.Config)

	// Server section.
	cfg.Server = new(sConfig.Server)
	cfg.Server.Identifier = n
	cfg.Server.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", k.lastPort)}
	cfg.Server.DataDir = filepath.Join(k.baseDir, n)
	cfg.Server.IsProvider = isProvider

	// Logging section.
	cfg.Logging = new(sConfig.Logging)
	cfg.Logging.File = serverLogFile
	cfg.Logging.Level = "DEBUG"

	// Debug section.
	cfg.Debug = new(sConfig.Debug)
	cfg.Debug.DisableRateLimit = true
	identity, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return err
	}
	cfg.Debug.IdentityKey = identity

	if isVoting {
		cfg.PKI = &sConfig.PKI{
			Voting: &sConfig.Voting{Peers: k.votingPeers()},
		}
	} else {
		cfg.PKI = new(sConfig.PKI)
		cfg.PKI.Nonvoting = new(sConfig.Nonvoting)
		cfg.PKI.Nonvoting.Address = fmt.Sprintf("127.0.0.1:%d", k.authPort)
		if k.authIdentity == nil {
		}
		idKey, err := k.authIdentity.PublicKey().MarshalText()
		if err != nil {
			return err
		}
		cfg.PKI.Nonvoting.PublicKey = string(idKey)
	}

	if isProvider {
		// Enable the thwack interface.
		cfg.Management = new(sConfig.Management)
		cfg.Management.Enable = true

		k.providerIdx++

		cfg.Provider = new(sConfig.Provider)

		loopCfg := new(sConfig.Kaetzchen)
		loopCfg.Capability = "loop"
		loopCfg.Endpoint = "+loop"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, loopCfg)

		keysvrCfg := new(sConfig.Kaetzchen)
		keysvrCfg.Capability = "keyserver"
		keysvrCfg.Endpoint = "+keyserver"
		cfg.Provider.Kaetzchen = append(cfg.Provider.Kaetzchen, keysvrCfg)

		// Enable HTTP user registration.
		k.lastPort++
		cfg.Provider.EnableUserRegistrationHTTP = true
		cfg.Provider.UserRegistrationHTTPAddresses = []string{fmt.Sprintf("127.0.0.1:%v", k.lastPort)}
		cfg.Provider.AdvertiseUserRegistrationHTTPAddresses = []string{fmt.Sprintf("http://127.0.0.1:%v", k.lastPort)}

		// Enable panda service, if available.
		panda_bin, err := exec.LookPath("panda_server")
		if err == nil {
			pandaCfg := new(sConfig.CBORPluginKaetzchen)
			pandaCfg.Capability = "panda"
			pandaCfg.Endpoint = "+panda"
			pandaCfg.Command = panda_bin
			pandaCfg.Config = map[string]interface{}{
				"log_dir":           path.Join(k.baseDir, n),
				"log_level":         "DEBUG",
				"writeBackInterval": "1h",
				"fileStore":         path.Join(k.baseDir, n, "panda.storage"),
				"dwell_time":        "200h",
			}
			pandaCfg.MaxConcurrency = 1
			pandaCfg.Disable = false
			cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, pandaCfg)
		} // panda_server not available

		// Enable memspool service, if available.
		memspool_bin, err := exec.LookPath("memspool")
		if err == nil {
			spoolCfg := new(sConfig.CBORPluginKaetzchen)
			spoolCfg.Capability = "spool"
			spoolCfg.Endpoint = "+spool"
			spoolCfg.Command = memspool_bin
			spoolCfg.Config = map[string]interface{}{
				"log_dir":    path.Join(k.baseDir, n),
				"data_store": path.Join(k.baseDir, n, "memspool.storage"),
			}
			spoolCfg.MaxConcurrency = 1
			spoolCfg.Disable = false
			cfg.Provider.CBORPluginKaetzchen = append(cfg.Provider.CBORPluginKaetzchen, spoolCfg)
		} // memspool not available
	} else {
		k.nodeIdx++
	}
	k.nodeConfigs = append(k.nodeConfigs, cfg)
	k.lastPort++
	err = cfg.FixupAndValidate()
	if err != nil {
		return err
	}
	return nil
}

func (k *Kimchi) genAuthConfig() error {
	const authLogFile = "authority.log"

	// create nonvoting config.Parameters from generic parameters
	parameters := &aConfig.Parameters{
		SendRatePerMinute: k.parameters.SendRatePerMinute,
		Mu:                k.parameters.Mu,
		MuMaxDelay:        k.parameters.MuMaxDelay,
		LambdaP:           k.parameters.LambdaP,
		LambdaPMaxDelay:   k.parameters.LambdaPMaxDelay,
		LambdaL:           k.parameters.LambdaL,
		LambdaLMaxDelay:   k.parameters.LambdaLMaxDelay,
	}

	cfg := new(aConfig.Config)

	// Authority section.
	cfg.Authority = new(aConfig.Authority)
	cfg.Authority.Addresses = []string{fmt.Sprintf("127.0.0.1:%d", k.lastPort)}
	k.lastPort++
	cfg.Authority.DataDir = filepath.Join(k.baseDir, "authority")

	// Parameters section.
	cfg.Parameters = parameters

	// Logging section.
	cfg.Logging = new(aConfig.Logging)
	cfg.Logging.File = authLogFile
	cfg.Logging.Level = "DEBUG"

	// Mkdir
	if err := os.Mkdir(cfg.Authority.DataDir, 0700); err != nil {
		return err
	}

	// Generate Keys
	idKey, err := eddsa.NewKeypair(rand.Reader)
	k.authIdentity = idKey
	if err != nil {
		return err
	}

	// Debug section.
	cfg.Debug = new(aConfig.Debug)
	cfg.Debug.IdentityKey = idKey

	if err := cfg.FixupAndValidate(); err != nil {
		return err
	}
	k.authConfig = cfg
	return nil
}

func (k *Kimchi) generateWhitelist() ([]*aConfig.Node, []*aConfig.Node, error) {
	mixes := []*aConfig.Node{}
	providers := []*aConfig.Node{}
	for _, nodeCfg := range k.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &aConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &aConfig.Node{
			IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil

}

// generateWhitelist returns providers, mixes, error
func (k *Kimchi) generateVotingWhitelist() ([]*vConfig.Node, []*vConfig.Node, error) {
	mixes := []*vConfig.Node{}
	providers := []*vConfig.Node{}
	for _, nodeCfg := range k.nodeConfigs {
		if nodeCfg.Server.IsProvider {
			provider := &vConfig.Node{
				Identifier:  nodeCfg.Server.Identifier,
				IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
			}
			providers = append(providers, provider)
			continue
		}
		mix := &vConfig.Node{
			IdentityKey: nodeCfg.Debug.IdentityKey.PublicKey(),
		}
		mixes = append(mixes, mix)
	}

	return providers, mixes, nil
}

func (k *Kimchi) runNonvoting() error {
	a := k.authConfig
	a.FixupAndValidate()
	server, err := aServer.New(a)
	if err != nil {
		return err
	}
	go k.LogTailer("nonvoting", filepath.Join(a.Authority.DataDir, a.Logging.File))
	k.servers = append(k.servers, server)
	return nil
}

func (k *Kimchi) runVotingAuthorities() error {
	for _, vCfg := range k.votingAuthConfigs {
		vCfg.FixupAndValidate()
		server, err := vServer.New(vCfg)
		if err != nil {
			return err
		}
		go k.LogTailer(vCfg.Authority.Identifier, filepath.Join(vCfg.Authority.DataDir, vCfg.Logging.File))
		k.servers = append(k.servers, server)
	}
	return nil
}

func (k *Kimchi) thwackUser(provider *sConfig.Config, user string, pubKey *ecdh.PublicKey) error {
	log.Printf("Attempting to add user: %v@%v", user, provider.Server.Identifier)

	sockFn := filepath.Join(provider.Server.DataDir, "management_sock")
	c, err := textproto.Dial("unix", sockFn)
	if err != nil {
		return err
	}
	defer c.Close()

	if _, _, err = c.ReadResponse(int(thwack.StatusServiceReady)); err != nil {
		return err
	}

	for _, v := range []string{
		fmt.Sprintf("ADD_USER %v %v", user, pubKey),
		fmt.Sprintf("SET_USER_IDENTITY %v %v", user, pubKey),
		"QUIT",
	} {
		if err = c.PrintfLine("%v", v); err != nil {
			return err
		}
		if _, _, err = c.ReadResponse(int(thwack.StatusOk)); err != nil {
			return err
		}
	}

	return nil
}

func (k *Kimchi) LogTailer(prefix, path string) {
	k.Add(1)
	defer k.Done()

	l := log.New(k.logWriter, prefix+" ", 0)
	t, err := tail.TailFile(path, tailConfig)
	defer t.Cleanup()
	if err != nil {
		log.Fatalf("Failed to tail file '%v': %v", path, err)
	}

	k.Lock()
	k.tails = append(k.tails, t)
	k.Unlock()

	for line := range t.Lines {
		l.Print(line.Text)
	}
}

func (k *Kimchi) Shutdown() {
	for _, svr := range k.servers {
		svr.Shutdown()
	}
	for _, t := range k.tails {
		t.StopAtEOF()
	}
	k.Wait()
	log.Printf("Terminated.")
}

func (k *Kimchi) RunWithDelayedAuthority(delay time.Duration) {
	// Launch all the nodes.
	for _, v := range k.nodeConfigs {
		v.FixupAndValidate()
		svr, err := nServer.New(v)
		if err != nil {
			log.Fatalf("Failed to launch node: %v", err)
		}

		k.servers = append(k.servers, svr)
		go k.LogTailer(v.Server.Identifier, filepath.Join(v.Server.DataDir, v.Logging.File))
	}

	f := func(vCfg *vConfig.Config) {
		vCfg.FixupAndValidate()
		server, err := vServer.New(vCfg)
		if err != nil {
			return
		}
		go k.LogTailer(vCfg.Authority.Identifier, filepath.Join(vCfg.Authority.DataDir, vCfg.Logging.File))
		k.servers = append(k.servers, server)
	}

	for _, vCfg := range k.votingAuthConfigs[:len(k.votingAuthConfigs)-1] {
		f(vCfg)
	}
	go func() {
		// delay starting the last authority from another routine
		<-time.After(delay)
		f(k.votingAuthConfigs[len(k.votingAuthConfigs)-1])
	}()
}

// GetClientConfig returns a client.Config and configures the client Account
func (k *Kimchi) GetClientConfig() (*cConfig.Config, string, *ecdh.PrivateKey, error) {
	if cfg, err := k.GetClientNetconfig(); err == nil {
		// use thwack to create a random user account and populate the cfg
		if cfg, privKey, err := k.registerClientAccount(cfg); err == nil {
			return cfg, cfg.Account.User, privKey, err
		} else {
			return nil, "", nil, err
		}
	} else {
		return nil, "", nil, err
	}
}

// GetCatshadowConfig returns a catshadow client configuration
func (k *Kimchi) GetCatshadowConfig() (*csConfig.Config, error) {
	cCfg, err := k.GetClientNetconfig()
	if err == nil {
		cfg := &csConfig.Config{
			Logging:            cCfg.Logging,
			UpstreamProxy:      cCfg.UpstreamProxy,
			Debug:              cCfg.Debug,
			NonvotingAuthority: cCfg.NonvotingAuthority,
			VotingAuthority:    cCfg.VotingAuthority,
			Panda:              cCfg.Panda,
		}
		return cfg, err
	}
	return nil, err
}

// GetClientNetconfig returns a client.Config populated with PKI information
func (k *Kimchi) GetClientNetconfig() (*cConfig.Config, error) {
	cfg := new(cConfig.Config)
	cfg.UpstreamProxy = &cConfig.UpstreamProxy{Type: "none"}
	cfg.Debug = &cConfig.Debug{
		DisableDecoyTraffic: true,
		PollingInterval:     10,
	}

	// authority section
	if k.voting {
		p, err := sConfig.AuthorityPeersFromPeers(k.votingPeers())
		if err != nil {
			return nil, err
		}
		cfg.VotingAuthority = &cConfig.VotingAuthority{
			Peers: p,
		}
	} else {
		cfg.NonvotingAuthority = &cConfig.NonvotingAuthority{
			Address:   k.authConfig.Authority.Addresses[0],
			PublicKey: k.authIdentity.PublicKey(),
		}
	}
	if err := cfg.FixupAndMinimallyValidate(); err == nil {
		return cfg, nil
	} else {
		return nil, err
	}
}

// registerClientAccount creates an account on a provider from the configuration
func (k *Kimchi) registerClientAccount(cfg *cConfig.Config) (*cConfig.Config, *ecdh.PrivateKey, error) {
	// select a username for the user
	cfg.Account = &cConfig.Account{}
	m := rand.NewMath()
	cfg.Account.User = fmt.Sprintf("user-%d", m.Intn(255))

	// configure logging for the user
	cfg.Logging = &cConfig.Logging{
		Disable: false,
		File:    filepath.Join(k.baseDir, cfg.Account.User+".log"),
		Level:   "DEBUG",
	}

	// find a provider
	for _, nCfg := range k.nodeConfigs {
		if nCfg.Server.IsProvider {
			cfg.Account.Provider = nCfg.Server.Identifier
			cfg.Account.ProviderKeyPin = nCfg.Debug.IdentityKey.PublicKey()
			cfg.Registration = &cConfig.Registration{} // not used
			cfg.Registration.Address = nCfg.Provider.UserRegistrationHTTPAddresses[0]

			// Generate keys for the account
			linkKey, err := ecdh.NewKeypair(m)
			if err != nil {
				return nil, nil, err
			}
			if err := cfg.FixupAndValidate(); err != nil {
				return nil, nil, err
			}

			// register the account on the provider
			if err := k.thwackUser(nCfg, cfg.Account.User, linkKey.PublicKey()); err != nil {
				return nil, nil, err
			}
			return cfg, linkKey, nil
		}
	}
	return nil, nil, errors.New("no providers found")
}

func retry(p pki.Client, epoch uint64, retries int) (reply []byte, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	for i := 0; i < retries; i++ {
		_, reply, err = p.Get(ctx, epoch)
		if err == nil {
			return
		}
	}
	return
}
