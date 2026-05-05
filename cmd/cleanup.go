/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/daeuniverse/dae/common/consts"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func init() {
	rootCmd.AddCommand(cleanupCmd)
}

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Clean up leftover eBPF TC filters and netns from a crashed dae session.",
	Long: `Clean up leftover eBPF TC filters and netns from a crashed dae session.

When dae is force-killed (e.g., kill -9), the eBPF programs attached to network
interfaces are not detached. This causes all network traffic passing through
those interfaces to be intercepted by a non-existent userspace handler,
leading to connection timeouts.

This command cleans up:
  - All TC filters with the "dae_" prefix on all interfaces
  - The dae0 veth pair
  - The daens network namespace
  - Any leftover ip rules with dae's fwmark

Run this as root before restarting dae after a crash.`,
	Run: func(cmd *cobra.Command, args []string) {
		log := logrus.New()
		log.SetLevel(logrus.InfoLevel)

		if os.Geteuid() != 0 {
			log.Fatalln("cleanup command requires root privileges")
		}

		if err := cleanupBpfFilters(log); err != nil {
			log.Warnf("Error cleaning up BPF filters: %v", err)
		}
		if err := cleanupNetns(log); err != nil {
			log.Warnf("Error cleaning up netns: %v", err)
		}

		log.Infoln("Cleanup completed.")
	},
}

func cleanupBpfFilters(log *logrus.Logger) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("failed to list links: %w", err)
	}

	parents := []uint32{
		netlink.HANDLE_MIN_INGRESS,
		netlink.HANDLE_MIN_EGRESS,
	}

	deleted := 0
	for _, link := range links {
		for _, parent := range parents {
			filters, err := netlink.FilterList(link, parent)
			if err != nil {
				// Some interfaces don't support TC (e.g., loopback), skip silently.
				continue
			}
			for _, f := range filters {
				bpfFilter, ok := f.(*netlink.BpfFilter)
				if !ok {
					continue
				}
				if !strings.HasPrefix(bpfFilter.Name, consts.AppName+"_") {
					continue
				}
				log.Infof("Deleting filter %q on %v (parent=%v)",
					bpfFilter.Name, link.Attrs().Name, parentString(parent))
				if err := netlink.FilterDel(bpfFilter); err != nil {
					if !os.IsNotExist(err) {
						log.Warnf("  Failed: %v", err)
					}
				} else {
					deleted++
				}
			}
		}
	}

	if deleted == 0 {
		log.Infoln("No leftover dae BPF filters found.")
	} else {
		log.Infof("Deleted %d dae BPF filter(s).", deleted)
	}
	return nil
}

func cleanupNetns(log *logrus.Logger) error {
	// Delete the veth pair (dae0).
	link, err := netlink.LinkByName("dae0")
	if err == nil {
		log.Infoln("Deleting link dae0 (veth pair dae0 <-> dae0peer)")
		if err := netlink.LinkDel(link); err != nil {
			log.Warnf("Failed to delete dae0 link: %v", err)
		}
	}

	// Unmount and remove the named netns.
	namedPath := path.Join("/run/netns", "daens")
	if _, err := os.Stat(namedPath); err == nil {
		log.Infoln("Deleting netns daens")
		_ = unix.Unmount(namedPath, unix.MNT_DETACH|unix.MNT_FORCE)
		if err := os.Remove(namedPath); err != nil {
			log.Warnf("Failed to remove netns daens: %v", err)
		}
	}

	// Also clean up any leftover rule/route with dae's mark.
	cleanupRules(log)

	return nil
}

func cleanupRules(log *logrus.Logger) {
	// Try to delete the ip rules that dae adds (fwmark 0x8000000).
	rules, err := netlink.RuleList(unix.AF_INET)
	if err == nil {
		for _, rule := range rules {
			if rule.Mark == int(consts.TproxyMark) {
				log.Infof("Deleting IPv4 rule: fwmark 0x%x table %d", rule.Mark, rule.Table)
				_ = netlink.RuleDel(&rule)
			}
		}
	}
	rules6, err := netlink.RuleList(unix.AF_INET6)
	if err == nil {
		for _, rule := range rules6 {
			if rule.Mark == int(consts.TproxyMark) {
				log.Infof("Deleting IPv6 rule: fwmark 0x%x table %d", rule.Mark, rule.Table)
				_ = netlink.RuleDel(&rule)
			}
		}
	}
}

func parentString(parent uint32) string {
	switch parent {
	case netlink.HANDLE_MIN_INGRESS:
		return "ingress"
	case netlink.HANDLE_MIN_EGRESS:
		return "egress"
	default:
		return fmt.Sprintf("0x%x", parent)
	}
}
