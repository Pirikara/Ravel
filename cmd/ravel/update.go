package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/Pirikara/Ravel/internal/update"
)

func runUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.Bool("check", false, "check for updates without installing")
	channel := fs.String("channel", "auto", "auto, stable, or beta")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || *channel != "auto" && *channel != "stable" && *channel != "beta" {
		usage()
		return 2
	}
	current := buildVersion()
	selected := *channel
	if selected == "auto" {
		selected = "stable"
		if current == "dev" || strings.Contains(current, "-") {
			selected = "beta"
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client := update.NewClient(current)
	release, err := client.Latest(ctx, selected)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if current != "dev" {
		comparison, err := update.Compare(current, release.Tag)
		if err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		if comparison >= 0 {
			fmt.Printf("ravel %s is up to date for the %s channel (latest: %s)\n", current, selected, release.Tag)
			return 0
		}
	}
	fmt.Printf("ravel update available: %s -> %s (%s channel)\n", current, release.Tag, selected)
	if *check {
		return 0
	}
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	switch update.Classify(executable, version) {
	case update.Homebrew:
		if err := upgradeHomebrew(ctx, release.Tag); err != nil {
			fmt.Fprintln(os.Stderr, "ravel:", err)
			return 1
		}
		fmt.Printf("ravel updated through Homebrew to %s\n", release.Tag)
		return 0
	case update.Container:
		fmt.Printf("Update this container image with: docker pull ghcr.io/pirikara/ravel:%s\n", release.Tag)
		return 0
	case update.GoBuild:
		fmt.Printf("Update this Go/source installation with: go install github.com/Pirikara/Ravel/cmd/ravel@%s\n", release.Tag)
		return 0
	}
	archiveName, err := update.ArchiveName(release.Tag, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if runtime.GOOS == "windows" {
		fmt.Printf("Download and install the verified archive: https://github.com/Pirikara/Ravel/releases/download/%s/%s\n", release.Tag, archiveName)
		return 0
	}
	archive, err := client.DownloadArchive(ctx, release, archiveName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	if err := update.Install(ctx, release, archive, executable); err != nil {
		fmt.Fprintln(os.Stderr, "ravel:", err)
		return 1
	}
	fmt.Printf("ravel updated to %s\n", release.Tag)
	return 0
}

func upgradeHomebrew(ctx context.Context, tag string) error {
	cmd := exec.CommandContext(ctx, "brew", "upgrade", "pirikara/tap/ravel")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("Homebrew upgrade failed: %w", err)
	}
	installed, err := exec.CommandContext(ctx, "brew", "list", "--versions", "pirikara/tap/ravel").Output()
	if err != nil {
		return fmt.Errorf("cannot verify Homebrew version: %w", err)
	}
	if !strings.Contains(" "+strings.TrimSpace(string(installed))+" ", " "+strings.TrimPrefix(tag, "v")+" ") {
		return fmt.Errorf("Homebrew tap does not yet provide %s", tag)
	}
	return nil
}
