package cmd

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/ilibs/json5"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/resolver/common"
	"github.com/DNS-MSMT-INET/yodns/resolver/runner"
	"golang.org/x/exp/slices"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func Test_main(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
			panic(r)
		}
	}()

	go func() { _ = http.ListenAndServe("localhost:8081", nil) }()

	// https://tip.golang.org/doc/gc-guide#The_GC_cycle
	// Going from 100 -> 200, CPU goes from 13.5% -> 8.5%
	// Going from 100 -> 50, CPU goes from 13.5% -> 16%

	debug.SetGCPercent(200)
	runtime.GOMAXPROCS(16)

	// t.Skip()

	configFilePath := "../config/ttlscacheme/runconfig.json5"
	inputFilePath := "../config/ttlscacheme/alexa_top.csv"
	outPath := "../data/testing/out"

	testTimeout := 5 * time.Minute

	options := runner.DefaultOptions
	bytes, err := os.ReadFile(configFilePath)
	if err != nil {
		panic(fmt.Errorf("error reading config file from %v with err %w", configFilePath, err))
	}
	if err := json5.Unmarshal(bytes, &options); err != nil {
		panic(fmt.Errorf("error parsing config file %v with err %w", configFilePath, err))
	}
	options.Input.Path = inputFilePath
	options.Output.Path = outPath
	options.EnableICMP = false
	if options.ICMPOutPath != "" {
		options.ICMPOutPath = path.Join("../", options.ICMPOutPath)
	}
	if options.Logfile != "" {
		options.Logfile = path.Join("../", options.Logfile)
	}
	if options.Caching.InfraDumpFile != "" {
		options.Caching.InfraDumpFile = path.Join("../", options.Caching.InfraDumpFile)
	}
	if options.Metrics.ServerKeyPath != "" {
		options.Metrics.ServerKeyPath = path.Join("../", options.Metrics.ServerKeyPath)
	}
	if options.Metrics.ServerCrtPath != "" {
		options.Metrics.ServerCrtPath = path.Join("../", options.Metrics.ServerCrtPath)
	}

	finished := make(chan bool, 1)
	go func() {
		runner.Run(common.Background(), options)
		finished <- true
	}()
	select {
	case <-time.After(testTimeout):
		return
	case <-finished:
		return
	}
}

func Test_DecodeMsg(t *testing.T) {
	bytes, err := base64.StdEncoding.DecodeString(
		"5DuFAAABAAAAAQABB3BlZXJpbmcGc29jaWFsAAAcAAEHcGVlcmluZwZzb2NpYWwAAAYAAQAAADwAOQltY2xwMWgxczEDbWNsAmdnAApob3N0bWFzdGVyA21jbAJnZwB4hvkTAAAOEAAAAHgAEnUAAAAAPAAAKQTQAAAAAAAA")
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	msg := new(dns.Msg)
	err = msg.Unpack(bytes)

	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func Test_X(t *testing.T) {
	idx := 8939743
	bytes := make([]byte, 4)
	binary.BigEndian.PutUint32(bytes, uint32(idx))

	x := fmt.Sprintf(string(bytes))

	rev := binary.BigEndian.Uint32([]byte(x))
	fmt.Println(rev)

	client := new(dns.Client)
	client.Timeout = 5 * time.Second
	q := new(dns.Msg).SetQuestion("google.com.", dns.TypeAAAA)

	r1, _, _ := client.Exchange(q, "216.239.34.10:53")
	r2, _, _ := client.Exchange(q, "216.239.32.10:53")

	b1, _ := r1.Pack()
	b2, _ := r2.Pack()

	fmt.Println(string(b1) == string(b2))
	fmt.Println(slices.Equal(b1, b2))
}

func Test_PeeringSocial(t *testing.T) {
	client := new(dns.Client)
	client.Timeout = 5 * time.Second
	q := new(dns.Msg).SetQuestion("peering.social.", dns.TypeAAAA)
	q2 := new(dns.Msg).SetQuestion("peering.social.", dns.TypeAAAA)

	for i := 0; i < 100; i++ {
		var r1, r2 *dns.Msg
		go func() {
			r1, _, _ = client.Exchange(q, "[2a09:e1c1:efc1:1337::53]:53")
		}()
		go func() {
			r2, _, _ = client.Exchange(q2, "213.206.184.75:53")
		}()

		time.Sleep(5 * time.Second)

		for _, msg := range []*dns.Msg{r1, r2} {
			if len(msg.Answer) == 0 {
				t.Error("no answer for AAAA query")
			}
		}
	}
}
