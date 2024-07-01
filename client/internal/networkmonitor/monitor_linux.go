//go:build !android

package networkmonitor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

type interfaceMonitor struct {
	stateMutex      sync.RWMutex
	interfaceStates map[int32]bool
}

func newInterfaceMonitor() *interfaceMonitor {
	return &interfaceMonitor{
		interfaceStates: make(map[int32]bool),
	}
}

func (im *interfaceMonitor) handleNewLink(update netlink.LinkUpdate) (bool, error) {
	isUp := (update.IfInfomsg.Flags&syscall.IFF_RUNNING) != 0 && update.Link.Attrs().OperState != netlink.OperDown

	im.stateMutex.RLock()
	prevState, exists := im.interfaceStates[update.Index]
	im.stateMutex.RUnlock()

	if !exists || prevState != isUp {
		im.stateMutex.Lock()
		im.interfaceStates[update.Index] = isUp
		im.stateMutex.Unlock()

		if !isUp {
			log.Infof("Network monitor: monitored interface (%s) is down.", update.Link.Attrs().Name)
			return true, nil
		}
	}
	return false, nil
}

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop, callback func()) error {
	if nexthopv4.Intf == nil && nexthopv6.Intf == nil {
		return errors.New("no interfaces available")
	}

	linkChan := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	defer close(done)

	if err := netlink.LinkSubscribe(linkChan, done); err != nil {
		return fmt.Errorf("subscribe to link updates: %v", err)
	}

	routeChan := make(chan netlink.RouteUpdate)
	if err := netlink.RouteSubscribe(routeChan, done); err != nil {
		return fmt.Errorf("subscribe to route updates: %v", err)
	}

	im := newInterfaceMonitor()
	log.Info("Network monitor: started")
	for {
		select {
		case <-ctx.Done():
			return ErrStopped

		case update := <-linkChan:
			if (nexthopv4.Intf == nil || update.Index != int32(nexthopv4.Intf.Index)) && (nexthopv6.Intf == nil || update.Index != int32(nexthopv6.Intf.Index)) {
				continue
			}

			switch update.Header.Type {
			case syscall.RTM_DELLINK:
				log.Infof("Network monitor: monitored interface (%s) is gone", update.Link.Attrs().Name)
				go callback()
				return nil
			case syscall.RTM_NEWLINK:
				if shouldCallback, err := im.handleNewLink(update); err != nil {
					return err
				} else if shouldCallback {
					go callback()
					return nil
				}
			}

		// handle route changes
		case route := <-routeChan:
			// default route and main table
			if route.Dst != nil || route.Table != syscall.RT_TABLE_MAIN {
				continue
			}
			switch route.Type {
			// triggered on added/replaced routes
			case syscall.RTM_NEWROUTE:
				log.Infof("Network monitor: default route changed: via %s, interface %d", route.Gw, route.LinkIndex)
				go callback()
				return nil
			case syscall.RTM_DELROUTE:
				if nexthopv4.Intf != nil && route.Gw.Equal(nexthopv4.IP.AsSlice()) || nexthopv6.Intf != nil && route.Gw.Equal(nexthopv6.IP.AsSlice()) {
					log.Infof("Network monitor: default route removed: via %s, interface %d", route.Gw, route.LinkIndex)
					go callback()
					return nil
				}
			}
		}
	}
}
