package transport

import (
	"time"

	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

// Plain makes a DNS query over TCP or UDP (with TCP fallback)
type Plain struct {
	Common
	PreferTCP bool
	UDPBuffer uint16
	Timeout   time.Duration
}

func (p *Plain) Exchange(m *dns.Msg) (*dns.Msg, error) {
	// Pack request to measure size
	reqBuf, err := m.Pack()
	if err != nil {
		return nil, err
	}
	dnsRequestSize := len(reqBuf)

	tcpClient := dns.Client{Net: "tcp", Timeout: p.Timeout}
	if p.PreferTCP {
		reply, _, tcpErr := tcpClient.Exchange(m, p.Server)
		if tcpErr == nil && p.MeasureSizes {
			p.logSizes(dnsRequestSize, reply, true)
		}
		return reply, tcpErr
	}

	client := dns.Client{UDPSize: p.UDPBuffer, Timeout: p.Timeout}
	reply, _, err := client.Exchange(m, p.Server)

	usedTCP := false
	if reply != nil && reply.Truncated {
		log.Debugf("Truncated reply from %s for %s over UDP, retrying over TCP", p.Server, m.Question[0].String())
		reply, _, err = tcpClient.Exchange(m, p.Server)
		usedTCP = true
	}

	if err == nil && p.MeasureSizes {
		p.logSizes(dnsRequestSize, reply, usedTCP)
	}

	return reply, err
}

// logSizes logs packet sizes for measurements
func (p *Plain) logSizes(dnsRequestSize int, reply *dns.Msg, usedTCP bool) {
	if reply == nil {
		return
	}

	respBuf, err := reply.Pack()
	if err != nil {
		log.Warnf("Failed to pack response for size measurement: %v", err)
		return
	}
	dnsResponseSize := len(respBuf)

	// Estimate wire sizes (DNS message + protocol overhead)
	var wireRequestSize, wireResponseSize int
	if usedTCP {
		// TCP: 2-byte length prefix + DNS message
		wireRequestSize = 2 + dnsRequestSize
		wireResponseSize = 2 + dnsResponseSize
	} else {
		// UDP: just DNS message (no length prefix)
		wireRequestSize = dnsRequestSize
		wireResponseSize = dnsResponseSize
	}

	log.Infof("[SIZE] dns_req=%d dns_resp=%d wire_req=%d wire_resp=%d",
		dnsRequestSize, dnsResponseSize, wireRequestSize, wireResponseSize)
}

// Close is a no-op for the plain transport
func (p *Plain) Close() error {
	return nil
}
