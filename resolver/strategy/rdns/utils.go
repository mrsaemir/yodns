package rdns

import (
	"net/netip"

	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
)


func EnqueueRequestForSingleIp(
	job *resolver.ResolutionJob,
	ns *model.NameServer,
	question model.Question,
	carryOverArgs any,
	opts resolver.EnqueueOpts,
) {
	ip := job.PickRandomIpAddr(
		ns.IPAddresses.Items(),
		question,
		opts,
	)
	if ip == nil {
		ns.OnIPAddedOnce(
			question,
			func(ip netip.Addr) {
				job.EnqueueRequestIP(
					ns, ip, question, carryOverArgs, opts,
				)
			},
		)
	} else {
		job.EnqueueRequestIP(
			ns, *ip, question, carryOverArgs, opts)
	}
}


func EnqueueRequestForSingleNameServer(
	job *resolver.ResolutionJob,
	zone *model.Zone,
	question model.Question,
	carryOverArgs any,
	opts resolver.EnqueueOpts,
) {
	ns := job.PickRandomNameServer(
		zone.GetNameServers(),
		question,
		opts,
	)
	if ns == nil {
		zone.OnNameServerAddedOnce(
			question,
			func (ns *model.NameServer) {
				EnqueueRequestForSingleIp(
					job, ns, question, carryOverArgs, opts)
			},
		)
	} else {
		EnqueueRequestForSingleIp(job, ns, question, carryOverArgs, opts)
	}
}