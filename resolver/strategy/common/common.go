package common

import (
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"github.com/rs/zerolog"
)


type CarryOverArgs struct {
	Zone        *model.Zone
	DoNotFollow bool
}

func EnrichLog(log zerolog.Logger, originalQName model.DomainName, ns *model.NameServer, msgExchange model.MessageExchange) zerolog.Logger {
	logCtx := log.With().
		Str("fqdn", string(originalQName)).
		Str("ip", msgExchange.NameServerIP.String()).
		Str("nsName", string(ns.Name)).
		Str("corrId", msgExchange.Metadata.CorrelationId.String())

	if log.GetLevel() <= zerolog.InfoLevel {
		logCtx.Str("qName", string(msgExchange.OriginalQuestion.Name))
		logCtx.Uint16("qType", msgExchange.OriginalQuestion.Type)
		logCtx.Uint16("qClass", msgExchange.OriginalQuestion.Class)
	}

	if log.GetLevel() <= zerolog.DebugLevel {
		logCtx.Interface("msg", msgExchange)
	}

	return logCtx.Logger()
}