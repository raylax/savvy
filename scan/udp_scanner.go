package scan

import (
	"errors"
	"github.com/raylax/savvy/rule"
	"github.com/raylax/savvy/types"
	"github.com/raylax/savvy/util"
	"net"
	"time"
)

type udpScanner struct {
	options UdpOptions
}

func (s *udpScanner) Scan(task *types.Task) (Stat, *Result, error) {
	rules := rule.GetUdpRules(task.Port)

	var excludeRules []string
	matchRules := udpMaxMatchRules

	var result *Result
	var stat Stat

	for {
		r := rules.Pop()
		if r == nil {
			break
		}

		if matchRules <= 0 {
			break
		}

		matchRules--
		excludeRules = append(excludeRules, r.Name)
		stat.ExecuteRules = append(stat.ExecuteRules, r.Name)
		task.Logger.Debug("Executing rule " + r.Name)
		er, err := s.executeRule(r, task)
		if err != nil {
			task.Logger.Debug("Error executing rule " + r.Name + ": " + err.Error())
			continue
		}

		if er != nil {
			result = er
			if !result.Fallback {
				break
			}
		}

		pushFallbacks(r, rules)
	}

	return stat, result, nil

}

func (s *udpScanner) executeRule(r *rule.TaskRule, task *types.Task) (*Result, error) {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.ParseIP(task.IP),
		Port: task.Port,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	payload := util.DecodeBinaryStringToBytes(r.Payload)
	_, err = conn.Write(payload)
	if err != nil {
		return nil, err
	}

	var buf = make([]byte, s.options.ReadBufferSize)
	s.setReadDeadline(conn)
	n, err := conn.Read(buf)
	if n == 0 && err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, nil
		}
	}
	task.Logger.Debug("Received " + string(buf[:min(64, n)]))

	result := matchServices(r, buf[:n])
	if result != nil {
		return result, nil
	}

	return nil, nil
}

func (s *udpScanner) setReadDeadline(conn net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(s.options.ReadTimeoutMs) * time.Millisecond))
}
