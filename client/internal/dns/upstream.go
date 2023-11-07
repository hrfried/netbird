package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	failsTillDeact   = int32(5)
	reactivatePeriod = 30 * time.Second
	upstreamTimeout  = 15 * time.Second
)

type upstreamClient interface {
	ExchangeContext(ctx context.Context, m *dns.Msg, a string) (r *dns.Msg, rtt time.Duration, err error)
}

type upstreamResolver struct {
	ctx              context.Context
	cancel           context.CancelFunc
	upstreamClient   upstreamClient
	upstreamServers  []string
	disabled         bool
	failsCount       atomic.Int32
	failsTillDeact   int32
	mutex            sync.Mutex
	reactivatePeriod time.Duration
	upstreamTimeout  time.Duration
	lIP              net.IP
	lNet             *net.IPNet
	lName            string
	iIndex           int

	deactivate func()
	reactivate func()
}

func getInterfaceIndex(interfaceName string) (int, error) {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Errorf("unable to get interface by name error: %s", err)
		return 0, err
	}

	return iface.Index, nil
}

func newUpstreamResolver(parentCTX context.Context, interfaceName string, wgAddr string) *upstreamResolver {
	ctx, cancel := context.WithCancel(parentCTX)

	// Specify the local IP address you want to bind to
	localIP, localNet, err := net.ParseCIDR(wgAddr) // Should be our interface IP
	if err != nil {
		log.Errorf("error while parsing CIDR: %s", err)
	}
	index, err := getInterfaceIndex(interfaceName)
	log.Debugf("UpstreamResolver interface name: %s, index: %d, ip: %s", interfaceName, index, localIP)
	if err != nil {
		log.Debugf("unable to get interface index for %s: %s", interfaceName, err)
	}
	localIFaceIndex := index // Should be our interface index

	return &upstreamResolver{
		ctx:              ctx,
		cancel:           cancel,
		upstreamTimeout:  upstreamTimeout,
		reactivatePeriod: reactivatePeriod,
		failsTillDeact:   failsTillDeact,
		lIP:              localIP,
		lNet:             localNet,
		iIndex:           localIFaceIndex,
		lName:            interfaceName,
	}
}

// getClientPrivate returns a new DNS client bound to the local IP address of the Netbird interface
// This method is needed for iOS
func (u *upstreamResolver) getClientPrivate() *dns.Client {
	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{
			IP:   u.lIP,
			Port: 0, // Let the OS pick a free port
		},
		Timeout: upstreamTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var operr error
			fn := func(s uintptr) {
				operr = unix.SetsockoptInt(int(s), unix.IPPROTO_IP, unix.IP_BOUND_IF, u.iIndex)
			}

			if err := c.Control(fn); err != nil {
				return err
			}

			if operr != nil {
				log.Errorf("error while setting socket option: %s", operr)
			}

			return operr
		},
	}
	client := &dns.Client{
		Dialer: dialer,
	}
	return client
}

func (u *upstreamResolver) stop() {
	log.Debugf("stoping serving DNS for upstreams %s", u.upstreamServers)
	u.cancel()
}

// ServeDNS handles a DNS request
func (u *upstreamResolver) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	defer u.checkUpstreamFails()

	log.WithField("question", r.Question[0]).Trace("received an upstream question")

	select {
	case <-u.ctx.Done():
		return
	default:
	}

	for _, upstream := range u.upstreamServers {
		var (
			err error
			t   time.Duration
			rm  *dns.Msg
		)

		upstreamExchangeClient := &dns.Client{}
		if runtime.GOOS != "ios" {
			ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
			rm, t, err = upstreamExchangeClient.ExchangeContext(ctx, r, upstream)
			cancel()
		} else {
			upstreamHost, _, err := net.SplitHostPort(upstream)
			if err != nil {
				log.Errorf("error while parsing upstream host: %s", err)
			}
			upstreamIP := net.ParseIP(upstreamHost)
			if u.lNet.Contains(upstreamIP) || net.IP.IsPrivate(upstreamIP) {
				log.Debugf("using private client to query upstream: %s", upstream)
				upstreamExchangeClient = u.getClientPrivate()
			}
			rm, t, err = upstreamExchangeClient.Exchange(r, upstream)
		}

		if err != nil {
			if err == context.DeadlineExceeded || isTimeout(err) {
				log.WithError(err).WithField("upstream", upstream).
					Warn("got an error while connecting to upstream")
				continue
			}
			u.failsCount.Add(1)
			log.WithError(err).WithField("upstream", upstream).
				Error("got other error while querying the upstream")
			return
		}

		if rm == nil {
			log.WithError(err).WithField("upstream", upstream).
				Warn("no response from upstream")
			return
		}
		// those checks need to be independent of each other due to memory address issues
		if !rm.Response {
			log.WithError(err).WithField("upstream", upstream).
				Warn("no response from upstream")
			return
		}

		log.Tracef("took %s to query the upstream %s", t, upstream)

		err = w.WriteMsg(rm)
		if err != nil {
			log.WithError(err).Error("got an error while writing the upstream resolver response")
		}
		// count the fails only if they happen sequentially
		u.failsCount.Store(0)
		return
	}
	u.failsCount.Add(1)
	log.Error("all queries to the upstream nameservers failed with timeout")
}

// checkUpstreamFails counts fails and disables or enables upstream resolving
//
// If fails count is greater that failsTillDeact, upstream resolving
// will be disabled for reactivatePeriod, after that time period fails counter
// will be reset and upstream will be reactivated.
func (u *upstreamResolver) checkUpstreamFails() {
	u.mutex.Lock()
	defer u.mutex.Unlock()

	if u.failsCount.Load() < u.failsTillDeact || u.disabled {
		return
	}

	select {
	case <-u.ctx.Done():
		return
	default:
		// todo test the deactivation logic, it seems to affect the client
		// log.Warnf("upstream resolving is disabled for %v", reactivatePeriod)
		// u.deactivate()
		// u.disabled = true
		// go u.waitUntilResponse()
	}
}

// waitUntilResponse retries, in an exponential interval, querying the upstream servers until it gets a positive response
func (u *upstreamResolver) waitUntilResponse() {
	exponentialBackOff := &backoff.ExponentialBackOff{
		InitialInterval:     500 * time.Millisecond,
		RandomizationFactor: 0.5,
		Multiplier:          1.1,
		MaxInterval:         u.reactivatePeriod,
		MaxElapsedTime:      0,
		Stop:                backoff.Stop,
		Clock:               backoff.SystemClock,
	}

	r := new(dns.Msg).SetQuestion("netbird.io.", dns.TypeA)

	operation := func() error {
		select {
		case <-u.ctx.Done():
			return backoff.Permanent(fmt.Errorf("exiting upstream retry loop for upstreams %s: parent context has been canceled", u.upstreamServers))
		default:
		}

		var err error
		for _, upstream := range u.upstreamServers {
			ctx, cancel := context.WithTimeout(u.ctx, u.upstreamTimeout)
			_, _, err = u.upstreamClient.ExchangeContext(ctx, r, upstream)

			cancel()

			if err == nil {
				return nil
			}
		}

		log.Tracef("checking connectivity with upstreams %s failed with error: %s. Retrying in %s", err, u.upstreamServers, exponentialBackOff.NextBackOff())
		return fmt.Errorf("got an error from upstream check call")
	}

	err := backoff.Retry(operation, exponentialBackOff)
	if err != nil {
		log.Warn(err)
		return
	}

	log.Infof("upstreams %s are responsive again. Adding them back to system", u.upstreamServers)
	u.failsCount.Store(0)
	u.reactivate()
	u.disabled = false
}

// isTimeout returns true if the given error is a network timeout error.
//
// Copied from k8s.io/apimachinery/pkg/util/net.IsTimeout
func isTimeout(err error) bool {
	var neterr net.Error
	if errors.As(err, &neterr) {
		return neterr != nil && neterr.Timeout()
	}
	return false
}
