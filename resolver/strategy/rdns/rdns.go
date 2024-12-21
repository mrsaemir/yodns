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
	referredToZones := s.updateZoneModel(job, q.Name, referrals, cargs.Zone, log)
	s.followReferrals(job, referredToZones, q, cargs)
	if q.Type != client.TypeNS {
		return
	}

	// TODO: case 5
}

func (s RDNS) followReferrals(
	job *resolver.ResolutionJob,
	referredToZones map[*model.Zone]any,
	q model.Question,
	cargs common.CarryOverArgs,
) {
	zones := make([]*model.Zone, 0, len(referredToZones))
	for zone := range referredToZones {
		zones = append(zones, zone)
	}

	// TODO: Handle cases where the required glue (for the NS) is missing. Ask the referring server for the IPs.
	// this issue gets worse when retrying. Refer to qmin.followReferrals for more info.

	// These requests are actually advancing the resolution
	for _, name := range job.GetNamesBelow(q.Name) {		
		zone := zones[0] // TODO: pick randomly?
		nextCargs := cargs
		nextCargs.Zone = zone

		if name.Equal(q.Name) {
			EnqueueRequestForSingleNameServer(
				job, zone, model.Ask(q.Name, client.TypeNS), nextCargs, resolver.EnqueueOpts{})
			continue
		}

		nextQName := name.GetAncestor(q.Name.GetLabelCount() + 1)
		EnqueueRequestForSingleNameServer(
			job, zone, model.Ask(nextQName, client.TypeNS), nextCargs, resolver.EnqueueOpts{})
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