package internal

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	"gitlab.mpi-klsb.mpg.de/fsteurer/yodns/client"
	"time"
)

func FormatWithPort(ip client.Address, port uint16) string {
	if ip.Is6() {
		return fmt.Sprintf("[%v]:%v", ip.String(), port)
	}

	return fmt.Sprintf("%v:%v", ip.String(), port)
}

func CreateWireMessage(q client.Question, disableEDNS0 bool, udpSize uint16, do bool) *dns.Msg {
	msgToSend := new(dns.Msg)
	msgToSend.SetQuestion(q.Name, q.Type)
	msgToSend.Question[0].Qclass = q.Class

	if disableEDNS0 {
		return msgToSend
	}

	msgToSend.SetEdns0(udpSize, do)

	return msgToSend
}

func SetTCPKeepalive(msgToSend *dns.Msg, keepAlive time.Duration) {
	opt := msgToSend.IsEdns0()
	if opt == nil {
		return
	}

	opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{
		Code:    dns.EDNS0TCPKEEPALIVE,
		Timeout: uint16(keepAlive / 100 / time.Millisecond), // Specified in units of 100 milliseconds (RFC7828)
	})
}

func ErrorResponse(correlationId uuid.UUID, connId uuid.UUID,
	nameServerIp client.Address,
	responseAddr string,
	rtt time.Duration,
	tcp bool,
	err error) client.Response {
	// An unsolicited response is a response that was not requested.
	// If the correlationId is nil, it should have been an UnsolicitedResponse.
	if correlationId == uuid.Nil {
		panic("CorrelationId may only be nil for unsolicited responses.")
	}

	return client.Response{
		CorrelationId: correlationId,
		Message:       nil,
		ConnId:        connId,
		ResponseAddr:  responseAddr,
		NameServerIP:  nameServerIp,
		Error:         err,
		RTT:           rtt,
		TCP:           tcp,
	}
}

func MessageResponse(correlationId uuid.UUID,
	connId uuid.UUID,
	nameServerIp client.Address,
	responseAddr string,
	responseMsg *dns.Msg,
	rtt time.Duration,
	tcp bool) client.Response {
	// An unsolicited response is a response that was not requested.
	// If the correlationId is nil, it should have been an UnsolicitedResponse.
	if correlationId == uuid.Nil {
		panic("CorrelationId may only be nil for unsolicited responses.")
	}

	return client.Response{
		CorrelationId: correlationId,
		Message:       responseMsg,
		ConnId:        connId,
		ResponseAddr:  responseAddr,
		NameServerIP:  nameServerIp,
		Error:         nil,
		RTT:           rtt,
		TCP:           tcp,
	}
}

// UnsolicitedResponse creates a response for an unsolicited or late message.
// Unsolicited messages are messages that cannot be correlated to a request,
// either because the request has already timed out,
// because the data was never requested in the first place,
// because the server set the wrong dns id in the response header or
// because the request has already been answered (duplicated response)
func UnsolicitedResponse(
	connId uuid.UUID,
	responseAddr string,
	responseMsg *dns.Msg,
	tcp bool) client.Response {
	return client.Response{
		CorrelationId: uuid.Nil,
		Message:       responseMsg,
		ConnId:        connId,
		ResponseAddr:  responseAddr,
		NameServerIP:  nil,
		Error:         nil,
		TCP:           tcp,
	}
}
