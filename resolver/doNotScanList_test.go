package resolver

import (
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/resolver/model"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func Test_doNotScanListWrapper_LoadFromReader(t *testing.T) {
	input := strings.NewReader("IP,192.0.2.1,withsomecomment" +
		"\nIP,2001:db8:fff::1," +
		"\nPREFIX,2001:db8::/64," +
		"\nPREFIX,198.51.100.0/24," +
		"\nDN,example.com,anothercomment")

	if err := DoNotScanList.FromReader(input); err != nil {
		t.Errorf("doNotScanListWrapper.FromReader() error = %v", err)
	}
	if _, ok := DoNotScanList.ips[netip.MustParseAddr("192.0.2.1")]; !ok {
		t.Errorf("Expected IPv4 to be loaded")
	}
	if _, ok := DoNotScanList.ips[netip.MustParseAddr("2001:db8:fff::1")]; !ok {
		t.Errorf("Expected IPv6 to be loaded")
	}
	if _, ok := DoNotScanList.names["example.com."]; !ok {
		t.Errorf("Expected Domainname to be loaded")
	}
	if _, ok := DoNotScanList.nets[netip.MustParsePrefix("198.51.100.0/24")]; !ok {
		t.Errorf("Expected IPv4 prefix to be loaded")
	}
	if _, ok := DoNotScanList.nets[netip.MustParsePrefix("2001:db8:0::/64")]; !ok {
		t.Errorf("Expected IPv6 prefix to be loaded")
	}
}

func Test_doNotScanListWrapper_CanReload(t *testing.T) {
	input := strings.NewReader("DN,example.com")
	input2 := strings.NewReader("DN,example.org")

	if err := DoNotScanList.FromReader(input); err != nil {
		t.Errorf("doNotScanListWrapper.FromReader() error = %v", err)
	}

	// Keep writing to trigger potential thread safety issues during the swap
	go func() {
		for {
			DoNotScanList.AddDomainName("example.net")
		}
	}()

	time.Sleep(20 * time.Millisecond)
	if err := DoNotScanList.FromReader(input2); err != nil {
		t.Errorf("doNotScanListWrapper.FromReader() error = %v", err)
	}
	if ok := DoNotScanList.MustNotScan(model.Question{}, "example.com.", netip.MustParseAddr("192.0.2.1")); ok {
		t.Errorf("Expected old domain name to be removed.")
	}
	if ok := DoNotScanList.MustNotScan(model.Question{}, "example.org.", netip.MustParseAddr("192.0.2.1")); !ok {
		t.Errorf("Expected new domain name to be loaded.")
	}
}

func Test_doNotScanListWrapper_MustNotScanIP_ExpectTrue(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddIP(netip.MustParseAddr("1.2.3.4"))
	mustNotScan := list.MustNotScan(model.Question{}, "", netip.MustParseAddr("1.2.3.4"))

	if !mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want true", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanIP_ExpectFalse(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddIP(netip.MustParseAddr("4.3.2.1"))
	mustNotScan := list.MustNotScan(model.Question{}, "", netip.MustParseAddr("1.2.3.4"))

	if mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want false", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanIP_EquivalentIPsWithDifferentFormat_ExpectTrue(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddIP(netip.MustParseAddr("ffff::1111"))
	mustNotScan := list.MustNotScan(model.Question{}, "", netip.MustParseAddr("FFFF:0000:0000::1111"))

	if !mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want false", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanIP_IPEqualToDomainName_ExpectFalse(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddDomainName("1.2.3.4")
	mustNotScan := list.MustNotScan(model.Question{}, "", netip.MustParseAddr("1.2.3.4"))

	if mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want false", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanDomainName_ExpectTrue(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddDomainName("a.b.c.")
	mustNotScan := list.MustNotScan(model.Question{
		Name:  "a.b.c.",
		Type:  0,
		Class: 0,
	}, "", netip.Addr{})

	if !mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want true", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanNsName_ExpectTrue(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddDomainName("a.b.c.")
	mustNotScan := list.MustNotScan(model.Question{}, "a.b.c.", netip.Addr{})

	if !mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want true", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanDomainName_ExpectFalse(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddIP(netip.MustParseAddr("1.2.3.4"))
	mustNotScan := list.MustNotScan(model.Question{}, "1.2.3.4", netip.Addr{})

	if mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want false", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanPrefix_ExpectTrue(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
		nets:  make(map[netip.Prefix]int),
	}

	list.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))

	mustNotScan := list.MustNotScan(model.Question{}, "", netip.MustParseAddr("192.0.2.123"))

	if !mustNotScan {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = %v, want true", mustNotScan)
	}
}

func Test_doNotScanListWrapper_MustNotScanPrefix_ExpectFalse(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
		nets:  make(map[netip.Prefix]int),
	}

	list.AddPrefix(netip.MustParsePrefix("192.0.2.0/24"))

	if list.MustNotScan(model.Question{}, "", netip.MustParseAddr("192.0.1.254")) {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = true, want false")
	}
	if list.MustNotScan(model.Question{}, "", netip.MustParseAddr("192.0.3.0")) {
		t.Errorf("doNotScanListWrapper.MustNotScan() got = true, want false")
	}
}

func Test_doNotScanListWrapper_MustNotScan(t *testing.T) {
	list := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		names: make(map[model.DomainName]int),
	}

	list.AddDomainName("must.not.scan.")
	list.AddIP(netip.MustParseAddr("1.2.3.4"))
	list.AddIP(netip.MustParseAddr("FFFF::FFFF"))

	type args struct {
		label  model.DomainName
		nsName model.DomainName
		nsIp   netip.Addr
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "AllowedToScan",
			want: false,
			args: args{
				label:  "allowed.to.scan.",
				nsName: "ns1.allowed.to.scan.",
				nsIp:   netip.MustParseAddr("4.3.2.1"),
			},
		},
		{
			name: "DoNotScanList_Contains_Label",
			want: true,
			args: args{
				label:  "must.not.scan.",
				nsName: "ns1.allowed.to.scan.",
				nsIp:   netip.MustParseAddr("4.3.2.1"),
			},
		},
		{
			name: "DoNotScanList_Contains_NameServerName",
			want: true,
			args: args{
				label:  "allowed.to.scan.",
				nsName: "must.not.scan.",
				nsIp:   netip.MustParseAddr("4.3.2.1"),
			},
		},
		{
			name: "DoNotScanList_ContainsIPV4",
			want: true,
			args: args{
				label:  "allowed.to.scan.",
				nsName: "ns1.allowed.to.scan.",
				nsIp:   netip.MustParseAddr("1.2.3.4"),
			},
		},
		{
			name: "DoNotScanList_ContainsIPV6",
			want: true,
			args: args{
				label:  "allowed.to.scan.",
				nsName: "ns1.allowed.to.scan.",
				nsIp:   netip.MustParseAddr("FFFF::FFFF"),
			},
		},
		{
			name: "DoNotScanList_ContainsIPV6WithDifferentFormat",
			want: true,
			args: args{
				label:  "allowed.to.scan.",
				nsName: "ns1.allowed.to.scan.",
				nsIp:   netip.MustParseAddr("FFFF:0000::FFFF"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			res := list.MustNotScan(model.Question{Name: tt.args.label}, tt.args.nsName, tt.args.nsIp)
			if res != tt.want {
				t.Errorf("MustNotScan() returned %v, expected %v.", res, tt.want)
			}
		})
	}
}
