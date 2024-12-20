package rdns

import "github.com/DNS-MSMT-INET/yodns/resolver/model"

func pickNameServer(nameservers []*model.NameServer) *model.NameServer {
	return nameservers[0]
}