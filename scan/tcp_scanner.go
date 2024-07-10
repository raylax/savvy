package scan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/raylax/savvy/rule"
	"github.com/raylax/savvy/types"
	"github.com/raylax/savvy/util"
	"net"
	"slices"
	"strings"
	"time"
)

const tcpRuleExecuteRetryCount = 3

type tcpScanner struct {
	options TcpOptions
}

func (s *tcpScanner) connect(task *types.Task) (net.Conn, error) {
	var d net.Dialer
	connectCtx, cancel := context.WithTimeout(task.Ctx, time.Duration(s.options.ConnectTimeoutMs)*time.Millisecond)
	conn, err := d.DialContext(connectCtx, "tcp", fmt.Sprintf("%s:%d", task.IP, task.Port))
	defer cancel()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (s *tcpScanner) connectSSL(task *types.Task) (net.Conn, []*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{
			Timeout: time.Duration(s.options.ConnectTimeoutMs) * time.Millisecond,
		},
		"tcp",
		fmt.Sprintf("%s:%d", task.IP, task.Port), &tls.Config{
			InsecureSkipVerify: true,
		},
	)
	if err != nil {
		task.Logger.Warn("Failed to connect to SSL", "error", err)
		return nil, nil, err
	}
	return conn, conn.ConnectionState().PeerCertificates, nil
}

func (s *tcpScanner) Scan(task *types.Task) (Stat, *Result, error) {
	rules := rule.GetTcpRules(task.Port)

	var excludeRules []string
	matchRules := tcpMaxMatchRules

	var result *Result
	var stat Stat

	sslMatched := false
	for {

		r := rules.Pop()
		if r == nil {
			break
		}

		if slices.Contains(excludeRules, r.Name) {
			logger.Debug("Skipping rule [" + r.Name + "]")
			continue
		}

		if matchRules <= 0 {
			break
		}

		if sslMatched && !r.SSL && result != nil {
			break
		}

		matchRules--
		excludeRules = append(excludeRules, r.Name)
		name := r.Name
		if r.SSL {
			name += "(SSL)"
		}
		task.Logger.Debug("Executing rule " + name)
		var er *Result
		var err error

		executeCount := 0

		stat.ExecuteRules = append(stat.ExecuteRules, r.Name)
		for {
			er, err = s.executeRule(r.SSL, r, task)
			if err == nil || executeCount >= tcpRuleExecuteRetryCount {
				break
			}

			if strings.Contains(err.Error(), "connection reset by peer") {
				executeCount++
				time.Sleep(time.Duration(s.options.ExecuteSleepMs) * time.Millisecond)
				continue
			}

			break
		}

		if err != nil {
			var connectErr *connectError
			if errors.As(err, &connectErr) {
				return stat, nil, connectErr.err
			}

			continue
		}
		if er != nil {
			sslMatched = r.SSL
			result = er
			if !result.Fallback {
				break
			}
		}

		pushFallbacks(r, rules)
	}

	return stat, result, nil
}

func (s *tcpScanner) executeRule(ssl bool, r *rule.TaskRule, task *types.Task) (*Result, error) {
	var conn net.Conn
	var err error
	var certs []*x509.Certificate
	if ssl {
		conn, certs, err = s.connectSSL(task)
	} else {
		conn, err = s.connect(task)

	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if r.Payload != "" {
		payload := util.DecodeBinaryStringToBytes(r.Payload)
		s.setWriteDeadline(conn)
		_, err := conn.Write(payload)
		if err != nil {
			return nil, err
		}
	}

	var buf = make([]byte, s.options.ReadBufferSize)
	s.setReadDeadline(conn)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
		return nil, err
	}

	result := matchServices(r, buf[:n])
	if result != nil {
		if ssl {
			result.Certs = certs
			result.SSL = true
		}
		return result, nil
	}

	return nil, nil
}

func (s *tcpScanner) setReadDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.options.ReadTimeoutMs) * time.Millisecond))
}

func (s *tcpScanner) setWriteDeadline(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(time.Duration(s.options.SendTimeoutMs) * time.Millisecond))
}
