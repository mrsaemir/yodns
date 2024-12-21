package rdns

import (
	"github.com/DNS-MSMT-INET/yodns/client"
	"github.com/DNS-MSMT-INET/yodns/resolver"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/DNS-MSMT-INET/yodns/resolver/strategy/common"
	"github.com/miekg/dns"
	"github.com/rs/zerolog"
)


type RDNS struct {
	messageAnalyzer common.MessageAnalyzer
	Modules common.ModuleCollection
}


func (s RDNS) AddModule(modules ...common.Module) RDNS {
	s.Modules = append(s.Modules, modules...)
	return s
}

func (s RDNS) OnInit(job *resolver.ResolutionJob) {
	EnqueueRequestForSingleNameServer(
		job, job.Root, model.Ask(".", client.TypeNS),
		common.CarryOverArgs{
			Zone: job.Root,
		},
		resolver.EnqueueOpts{},
	)
}

func (s RDNS) OnStartResolveName(job *resolver.ResolutionJob, sname model.DomainName) {}

func (s RDNS) OnResponse(job *resolver.ResolutionJob, msgEx model.MessageExchange, ns *model.NameServer, args any) {
	dnsMsg := msgEx.Message
	q := msgEx.OriginalQuestion

	// Enrich the logger with contextual information.
	log := common.EnrichLog(job.GetLog(), q.Name, ns, msgEx)

	isFullName := job.ContainsName(q.Name)

	cargs, isCargs := args.(common.CarryOverArgs)
	if !isCargs {
		log.Error().Msgf("Got unexpected args: %v", args)
		return
	}

	// We have to retry at a different server / IP 
	if msgEx.Error != nil {
		panic("Handle Retry")
	}

	/*
	 * Case 1: 	FullName + A/AAAA
	 * What:  	We've resolved the A/AAAA record of a full name
	 * Action: 	
	*/
	 if isFullName && (q.Type == client.TypeA || q.Type == client.TypeAAAA) && dnsMsg != nil {
		job.AddIPsToNameServer(&msgEx)
	}

	if cargs.DoNotFollow {
		return
	}

	/*
	 * Case 2:  FullName + not a referral
	 * What:  	We have asked a Nameserver and it did not respond with only a referral, indicating that it could be authoritative.
	 * Action:  
	 * Why:
	 */
	 if isFullName && q.Type == dns.TypeNS && (!s.messageAnalyzer.IsOnlyReferralFor(msgEx.Message, q.Name) || q.Name.Equal(cargs.Zone.Name)) {
		s.Modules.OnFullNameResolved(job, q.Name, cargs.Zone)
		return
	}

	// TODO: case 3: CNAME

	/*
	 * Case 4:  Referral or "self authoritative" answer
	 * What:  	The name server included nameservers in the authority or answer section
	 * Action:  
	*/
	referrals := s.messageAnalyzer.GetReferrals(dnsMsg, q.Type)
	s.updateZoneModel(job, q.Name, referrals, cargs.Zone, log)

	if q.Type != client.TypeNS {
		return
	}

	/*
	 * Case 5:  Non-referral answer for non-full name
	 * What:  	The name server responded without a referral for the name we queried. It's not necessarily a full name.
	 * Action:  Continue by asking for the next label.
	 * Why: 	We don't want to miss any queries. Unless the server clearly indicates,
	 *          that it is not authoritative for the zone, we continue asking for the next label.
	*/
	if (
		(dnsMsg == nil || (dnsMsg.Rcode != client.RcodeNotZone && dnsMsg.Rcode != client.RcodeNotAuth)) &&
		(!s.messageAnalyzer.IsOnlyReferral(dnsMsg) || cargs.Zone.HasNameServer(ns))) {
			for _, name := range job.GetNamesBelow(q.Name) {
				var nextQName model.DomainName
				if q.Name.Equal(name) {
					nextQName = q.Name
				} else {
					nextQName = name.GetAncestor(q.Name.GetLabelCount() + 1)
				}
	
				nextCargs := cargs
				nextCargs.Zone = job.Root.GetClosestEnclosingZone(nextQName)
				EnqueueRequestForSingleNameServer(
					job, nextCargs.Zone, model.Ask(nextQName, client.TypeNS), nextCargs, resolver.EnqueueOpts{})
			}
	}
}


func (s RDNS) updateZoneModel(
	job *resolver.ResolutionJob,
	qName model.DomainName,
	referrals []common.Referral,
	zone *model.Zone,
	log zerolog.Logger) map[*model.Zone]any {

	createdZones := make(map[*model.Zone]any, 1)
	referredToZones := make(map[*model.Zone]any, 1)
	newNameServers := make(map[*model.NameServer]any)

	for _, referral := range referrals {

		if !qName.IsSubDomainOf(referral.ZoneName) { // Bogus referral
			continue
		}

		nextZone, loaded, err := zone.CreateOrGetSubzone(referral.ZoneName)
		if err != nil { // Upward referral
			log.Debug().Msgf("Failed to create or get subzone %v from parent zone %v", referral.ZoneName, zone.Name)
			continue
		}

		if !loaded {
			createdZones[nextZone] = nil
		}
		referredToZones[nextZone] = nil

		ns, loaded := job.CreateOrGetNameServer(referral.NameServer)
		if !loaded {
			newNameServers[ns] = nil
		}

		nextZone.AppendNameServer(ns)

		// TODO - what if a CNAME exists for this NS?
		// e.g. ns1.example.com. CNAME ns2.example.com.
		// and we find glue for ns2.example.com - should we add it to ns1.example.com?
		ns.AddIPs(referral.Glue...)
	}

	for zone := range createdZones {
		s.Modules.OnZoneCreated(job, zone)
	}

	return referredToZones
}

func New() RDNS {
	return RDNS{
		messageAnalyzer: common.MessageAnalyzer{},
	}
}