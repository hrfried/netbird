package connection

import (
	"context"
	"github.com/pion/ice/v2"
	log "github.com/sirupsen/logrus"
	"github.com/wiretrustee/wiretrustee/iface"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"net"
	"time"
)

var (
	DefaultAllowedIps  = "0.0.0.0/0"
	DefaultWgKeepAlive = 20 * time.Second
)

type Config struct {
	// Local Wireguard listening address  e.g. 127.0.0.1:51820
	WgListenAddr string
	// A Local Wireguard Peer IP address in CIDR notation e.g. 10.30.30.1/24
	WgPeerIp string
	// Local Wireguard Interface name (e.g. wg0)
	WgIface string
	// Local Wireguard private key
	WgKey wgtypes.Key
	// Remote Wireguard public key
	RemoteWgKey wgtypes.Key

	StunTurnURLS []*ice.URL
}

type IceCredentials struct {
	uFrag         string
	pwd           string
	isControlling bool //todo think of better solution??
}

type Connection struct {
	Config Config
	// signalCandidate is a handler function to signal remote peer about local connection candidate
	signalCandidate func(candidate ice.Candidate) error

	// signalOffer is a handler function to signal remote peer our connection offer (credentials)
	signalOffer func(uFrag string, pwd string) error

	// signalOffer is a handler function to signal remote peer our connection answer (credentials)
	signalAnswer func(uFrag string, pwd string) error

	// remoteAuthChannel is a channel used to wait for remote credentials to proceed with the connection
	remoteAuthChannel chan IceCredentials

	closeChannel chan bool

	// agent is an actual ice.Agent that is used to negotiate and maintain a connection to a remote peer
	agent *ice.Agent
}

func NewConnection(config Config,
	signalCandidate func(candidate ice.Candidate) error,
	signalOffer func(uFrag string, pwd string) error,
	signalAnswer func(uFrag string, pwd string) error,
) *Connection {

	return &Connection{
		Config:            config,
		signalCandidate:   signalCandidate,
		signalOffer:       signalOffer,
		signalAnswer:      signalAnswer,
		remoteAuthChannel: make(chan IceCredentials, 1),
		closeChannel:      make(chan bool, 1),
		agent:             nil,
	}
}

// Open opens connection to a remote peer.
// Will block until the connection has successfully established
func (conn *Connection) Open() error {

	wgConn, err := conn.createWireguardProxy()
	if err != nil {
		return err
	}

	// create an ice Agent that will be responsible for negotiating and establishing actual peer-to-peer connection
	conn.agent, err = ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		Urls:         conn.Config.StunTurnURLS,
	})
	if err != nil {
		return err
	}

	err = conn.listenOnLocalCandidates()
	if err != nil {
		return err
	}

	err = conn.listenOnConnectionStateChanges()
	if err != nil {
		return err
	}

	err = conn.signalCredentials()
	if err != nil {
		return err
	}

	// wait until credentials have been sent from the remote peer (will arrive via signal channel)
	remoteAuth := <-conn.remoteAuthChannel

	err = conn.agent.GatherCandidates()
	if err != nil {
		return err
	}

	remoteConn, err := conn.openConnectionToRemote(remoteAuth.isControlling, remoteAuth)
	if err != nil {
		log.Errorf("failed establishing connection with the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
		return err
	}

	go conn.proxyToRemotePeer(*wgConn, remoteConn)
	go conn.proxyToLocalWireguard(*wgConn, remoteConn)

	return nil
}

func (conn *Connection) OnAnswer(remoteAuth IceCredentials) error {
	log.Debugf("onAnswer from peer %s", conn.Config.RemoteWgKey.String())
	conn.remoteAuthChannel <- remoteAuth
	return nil
}

func (conn *Connection) OnOffer(remoteAuth IceCredentials) error {

	uFrag, pwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	err = conn.signalAnswer(uFrag, pwd)
	if err != nil {
		return err
	}

	conn.remoteAuthChannel <- remoteAuth

	return nil
}

func (conn *Connection) OnRemoteCandidate(candidate ice.Candidate) error {

	log.Debugf("onRemoteCandidate  from peer %s -> %s", conn.Config.RemoteWgKey.String(), candidate.String())

	err := conn.agent.AddRemoteCandidate(candidate)
	if err != nil {
		return err
	}

	return nil
}

// openConnectionToRemote opens an ice.Conn to the remote peer. This is a real peer-to-peer connection
func (conn *Connection) openConnectionToRemote(isControlling bool, credentials IceCredentials) (*ice.Conn, error) {
	var realConn *ice.Conn
	var err error

	if isControlling {
		realConn, err = conn.agent.Dial(context.TODO(), credentials.uFrag, credentials.pwd)
	} else {
		realConn, err = conn.agent.Accept(context.TODO(), credentials.uFrag, credentials.pwd)
	}

	if err != nil {
		return nil, err
	}

	return realConn, err
}

// signalCredentials prepares local user credentials and signals them to the remote peer
func (conn *Connection) signalCredentials() error {
	localUFrag, localPwd, err := conn.agent.GetLocalUserCredentials()
	if err != nil {
		return err
	}

	err = conn.signalOffer(localUFrag, localPwd)
	if err != nil {
		return err
	}
	return nil
}

// listenOnLocalCandidates registers callback of an ICE Agent to new local connection candidates and
// signal them to the remote peer
func (conn *Connection) listenOnLocalCandidates() error {
	err := conn.agent.OnCandidate(func(candidate ice.Candidate) {
		if candidate != nil {

			log.Debugf("discovered local candidate %s", candidate.String())
			err := conn.signalCandidate(candidate)
			if err != nil {
				log.Errorf("failed signaling candidate to the remote peer %s %s", conn.Config.RemoteWgKey.String(), err)
				//todo ??
				return
			}
		}
	})

	if err != nil {
		return err
	}

	return nil
}

// listenOnConnectionStateChanges registers callback of an ICE Agent to track connection state
func (conn *Connection) listenOnConnectionStateChanges() error {
	err := conn.agent.OnConnectionStateChange(func(state ice.ConnectionState) {
		log.Debugf("ICE Connection State has changed: %s", state.String())
		if state == ice.ConnectionStateConnected {
			// once the connection has been established we can check the selected candidate pair
			pair, err := conn.agent.GetSelectedCandidatePair()
			if err != nil {
				log.Errorf("failed selecting active ICE candidate pair %s", err)
				return
			}
			log.Debugf("connected to peer %s via selected candidate pair %s", conn.Config.RemoteWgKey.String(), pair)
		}
	})

	if err != nil {
		return err
	}

	return nil
}

// createWireguardProxy opens connection to the local Wireguard instance (proxy) and sets peer endpoint of Wireguard to point
// to the local address of a proxy
func (conn *Connection) createWireguardProxy() (*net.Conn, error) {
	wgConn, err := net.Dial("udp", conn.Config.WgListenAddr)
	if err != nil {
		log.Fatalf("failed dialing to local Wireguard port %s", err)
		return nil, err
	}
	// add local proxy connection as a Wireguard peer
	err = iface.UpdatePeer(conn.Config.WgIface, conn.Config.RemoteWgKey.String(), DefaultAllowedIps, DefaultWgKeepAlive,
		wgConn.LocalAddr().String())
	if err != nil {
		log.Errorf("error while configuring Wireguard peer [%s] %s", conn.Config.RemoteWgKey.String(), err.Error())
		return nil, err
	}

	return &wgConn, err
}

// proxyToRemotePeer proxies everything from Wireguard to the remote peer
// blocks
func (conn *Connection) proxyToRemotePeer(wgConn net.Conn, remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		n, err := wgConn.Read(buf)
		if err != nil {
			log.Warnln("Error reading from peer: ", err.Error())
			continue
		}

		n, err = remoteConn.Write(buf[:n])
		if err != nil {
			log.Warnln("Error writing to remote peer: ", err.Error())
		}
	}
}

// proxyToLocalWireguard proxies everything from the remote peer to local Wireguard
// blocks
func (conn *Connection) proxyToLocalWireguard(wgConn net.Conn, remoteConn *ice.Conn) {

	buf := make([]byte, 1500)
	for {
		n, err := remoteConn.Read(buf)
		if err != nil {
			log.Errorf("failed reading from remote connection %s", err)
		}

		n, err = wgConn.Write(buf[:n])
		if err != nil {
			log.Errorf("failed writing to local Wireguard instance %s", err)
		}
	}
}