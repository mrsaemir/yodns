package resolver

import (
	"encoding/csv"
	"fmt"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
)

var doNotScanMu sync.RWMutex

// DoNotScanList is the list of all IPs and domain names which are exempt from scanning.
var DoNotScanList = doNotScanListWrapper{
	ips:   make(map[netip.Addr]int),
	nets:  make(map[netip.Prefix]int),
	names: make(map[model.DomainName]int),
}

type doNotScanListWrapper struct {
	ips   map[netip.Addr]int
	nets  map[netip.Prefix]int
	names map[model.DomainName]int
}

func (list *doNotScanListWrapper) FromFile(filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	return list.FromReader(f)
}

func (*doNotScanListWrapper) FromReader(r io.Reader) error {
	csvReader := csv.NewReader(r)
	allRecords, err := csvReader.ReadAll()
	if err != nil {
		return err
	}

	result := doNotScanListWrapper{
		ips:   make(map[netip.Addr]int),
		nets:  make(map[netip.Prefix]int),
		names: make(map[model.DomainName]int),
	}

	for _, record := range allRecords {
		if len(record) < 2 { // Class, Value and then comments/optional columns
			return fmt.Errorf("malformed entry %v in do not scan list", strings.Join(record, ","))
		}

		class := record[0] // IP, DN or PREFIX

		if strings.EqualFold(class, "IP") {
			if net.ParseIP(record[1]) == nil {
				return fmt.Errorf("value %v in do not scan list is not a valid IP", record[1])
			}

			result.AddIP(netip.MustParseAddr(record[1]))
		}

		if strings.EqualFold(class, "PREFIX") {
			p, err := netip.ParsePrefix(record[1])
			if err != nil {
				return fmt.Errorf("value %v in do not scan list is not a valid prefix", record[1])
			}
			result.AddPrefix(p)
		}

		if strings.EqualFold(class, "DN") {
			dn, err := model.NewDomainName(record[1])
			if err != nil {
				return fmt.Errorf("value %v in do not scan list is not a valid domain name: %w", record[1], err)
			}

			result.AddDomainName(dn)
		}
	}

	// Swap
	doNotScanMu.Lock()
	DoNotScanList = result
	doNotScanMu.Unlock()

	return nil
}

// AddIP adds an ip address to the do-not-scan-list. IPs on that list will never receive a request.
func (list *doNotScanListWrapper) AddIP(ip netip.Addr) {
	doNotScanMu.Lock()
	list.ips[ip] = 0 // We don't care about the value, the map is effectively used as a set
	doNotScanMu.Unlock()
}

// AddDomainName adds a domain name to the do-not-scan-list.
// If the resolver is about to resolve a zone having such a name, it will stop.
// The resolver will also not contact a name server with such a name (given that the name is known at the time)
func (list *doNotScanListWrapper) AddDomainName(domainName model.DomainName) {
	doNotScanMu.Lock()
	list.names[domainName] = 0 // We don't care about the value, the map is effectively used as a set
	doNotScanMu.Unlock()
}

// AddPrefix adds a IP prefix to the do-not-scan-list.
// IPs in that prefix list will never receive a request.
func (list *doNotScanListWrapper) AddPrefix(prefix netip.Prefix) {
	doNotScanMu.Lock()
	list.nets[prefix] = 0
	doNotScanMu.Unlock()
}

// MustNotScan returns true, if either the queried domain name, name server host name or name server IP are on the DoNotScan list.
func (list *doNotScanListWrapper) MustNotScan(q model.Question, nsName model.DomainName, nsIp netip.Addr) bool {
	doNotScanMu.RLock()
	defer doNotScanMu.RUnlock()

	for i := 1; i <= q.Name.GetLabelCount(); i++ {
		if _, isContained := list.names[q.Name.GetAncestor(i)]; isContained {
			return true
		}
	}

	for i := 1; i <= nsName.GetLabelCount(); i++ {
		n := nsName.GetAncestor(i)
		if _, isContained := list.names[n]; isContained {
			return true
		}
	}

	if _, isContained := list.ips[nsIp]; isContained {
		return true
	}

	for prefix := range list.nets {
		if prefix.Contains(nsIp) {
			return true
		}
	}

	return false
}
