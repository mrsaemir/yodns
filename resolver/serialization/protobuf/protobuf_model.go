package protobuf

import (
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/DNS-MSMT-INET/yodns/resolver/model"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/netip"
	"time"
)

const shortUUIDLength = 4
const longUUIDLength = 16

func (msg *MessageExchange) From(exchange *model.MessageExchange) error {
	msg.OriginalQuestion = &Question{
		Name:  string(exchange.OriginalQuestion.Name),
		Type:  uint32(exchange.OriginalQuestion.Type),
		Class: uint32(exchange.OriginalQuestion.Class),
	}
	msg.ResponseAddr = exchange.ResponseAddr
	msg.NameServerIp = exchange.NameServerIP.String()
	msg.Metadata = &Metadata{
		FromCache:     exchange.Metadata.FromCache,
		RetryIdx:      uint32(exchange.Metadata.RetryIdx),
		Tcp:           exchange.Metadata.TCP,
		CorrelationId: exchange.Metadata.CorrelationId[:],
		ParentId:      exchange.Metadata.ParentId[:],
		EnqueueTime:   timestamppb.New(exchange.Metadata.EnqueueTime),
		DequeueTime:   timestamppb.New(exchange.Metadata.DequeueTime),
		IsFinal:       exchange.Metadata.IsFinal,
		Rtt:           int64(exchange.Metadata.RTT),
	}

	// TODO: connID should be UUID not string to remove this ambiguity
	if connId, err := uuid.Parse(exchange.Metadata.ConnId); err == nil {
		msg.Metadata.ConnId = connId[:]
	} else {
		msg.Metadata.ConnId = []byte(exchange.Metadata.ConnId)
	}

	if exchange.Message != nil {
		if buf, err := exchange.Message.Pack(); err == nil {
			msg.Message = buf
		}
	}

	if exchange.Error != nil {
		msg.ErrorMessage = exchange.Error.Message
		msg.ErrorCode = string(exchange.Error.Code)
	}

	return nil
}

func (msg *MessageExchange) ToModel() (model.MessageExchange, error) {
	result := model.MessageExchange{
		OriginalQuestion: model.Question{
			Name:  model.MustNewDomainName(msg.OriginalQuestion.Name),
			Type:  uint16(msg.OriginalQuestion.Type),
			Class: uint16(msg.OriginalQuestion.Class),
		},
		ResponseAddr: msg.ResponseAddr,
		NameServerIP: netip.MustParseAddr(msg.NameServerIp),
		Metadata: model.Metadata{
			FromCache:   msg.Metadata.FromCache,
			RetryIdx:    uint(msg.Metadata.RetryIdx),
			TCP:         msg.Metadata.Tcp,
			EnqueueTime: msg.Metadata.EnqueueTime.AsTime(),
			DequeueTime: msg.Metadata.DequeueTime.AsTime(),
			IsFinal:     msg.Metadata.IsFinal,
			RTT:         time.Duration(msg.Metadata.Rtt),
		},
	}

	if len(msg.Message) > 0 {
		result.Message = new(dns.Msg)
		_ = result.Message.Unpack(msg.Message) // ignore the error (malformed messages may appear)
	}

	if msg.ErrorCode != "" || msg.ErrorMessage != "" {
		result.Error = &model.SendError{
			Message: msg.ErrorMessage,
			Code:    model.ErrorCode(msg.ErrorCode),
		}
	}

	var err error
	result.Metadata.CorrelationId, err = parseUUID(msg.Metadata.CorrelationId)
	if err != nil {
		return result, err
	}

	result.Metadata.ParentId, err = parseUUID(msg.Metadata.ParentId)
	if err != nil {
		return result, err
	}

	if len(msg.Metadata.ConnId) == 0 {
		result.Metadata.ConnId = ""
	} else if connID, err := parseUUID(msg.Metadata.ConnId); err == nil {
		result.Metadata.ConnId = connID.String()
	} else {
		result.Metadata.ConnId = string(msg.Metadata.ConnId)
	}

	return result, nil
}

func parseUUID(bytes []byte) (uuid.UUID, error) {
	// Default UUID length
	if len(bytes) == longUUIDLength {
		return uuid.FromBytes(bytes)
	}

	// Our "short UUID" is missing some bytes in the beginning to reduce storage needs.
	// Fill it up to full length before parsing
	if len(bytes) == shortUUIDLength {
		idBytes := make([]byte, longUUIDLength)
		copy(idBytes[longUUIDLength-shortUUIDLength:], bytes)
		return uuid.FromBytes(idBytes)
	}

	// Legacy: We used to store the uuid as string, but we still want to be able to parse the old files.
	return uuid.Parse(string(bytes))
}
