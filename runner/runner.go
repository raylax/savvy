package runner

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/raylax/savvy/log"
	"github.com/raylax/savvy/scan"
	"github.com/raylax/savvy/types"
	"github.com/samber/lo"
	"net/url"
	"os"
	"time"
)

const (
	maxServiceDetectionWorkers = 20
)

const (
	queueHostDetection         = "task.HostDetection"
	queueHostDetectionResul    = "task.HostDetectionResult"
	queueServiceDetection      = "task.ServiceDetection"
	queueServiceDetectionResul = "task.ServiceDetectionResult"
)

var logger = log.Root.With("module", "runner")

type Runner struct {
	amqpConn    *amqp.Connection
	amqpCh      *amqp.Channel
	hostScanner *scan.HostScanner
	tcpScanner  scan.Scanner
	udpScanner  scan.Scanner
	wg          *WorkerGroup
}

func NewRunner() *Runner {
	return &Runner{
		hostScanner: scan.NewHostScanner(),
		tcpScanner:  scan.NewTcpScanner(scan.TcpOptions{}),
		udpScanner:  scan.NewUdpScanner(scan.UdpOptions{}),
		wg:          NewWorkerGroup(maxServiceDetectionWorkers),
	}
}

func (r *Runner) Run() {
	err := r.initAMQP()
	defer r.amqpConn.Close()
	if err != nil {
		log.Root.Error("Error initializing AMQP", "error", err)
		return
	}

	logger.Info("Ready to receive tasks")
	select {}
}

func (r *Runner) initAMQP() error {

	amqpUrl, err := url.Parse(os.Args[1])
	if err != nil {
		return fmt.Errorf("parsing amqp url - %w", err)
	}

	conn, err := amqp.Dial(amqpUrl.String())
	if err != nil {
		return fmt.Errorf("dialing amqp - %w", err)
	}
	r.amqpConn = conn

	ch, err := conn.Channel()
	if err != nil {
		return fmt.Errorf("getting channel - %w", err)
	}
	r.amqpCh = ch

	err = handleConsumeMessage(
		ch,
		queueServiceDetection,
		r.handleServiceDetectionMessage,
	)

	if err != nil {
		return err
	}

	err = handleConsumeMessage(
		ch,
		queueHostDetection,
		r.handleHostDetectionMessage,
	)

	if err != nil {
		return err
	}

	return nil
}

func (r *Runner) handleHostDetectionMessage(message HostDetectionMessage) {
	logger.Info("Received host detection task", "id", message.ID, "protocol", message.Protocol)

	startTime := time.Now()
	var results []*scan.HostScanResult
	var err error
	switch message.Protocol {
	case "tcp":
		results, err = r.hostScanner.ScanTcp(context.Background(), message.IPs)
	case "udp":
		results, err = r.hostScanner.ScanUdp(context.Background(), message.IPs)
	default:
		logger.Error("Unknown protocol", "protocol", message.Protocol)
		return
	}

	if err != nil {
		logger.Error("Error host detection", "ips", message.IPs, "protocol", message.Protocol, "error", err)
		return
	}
	logger.Info("Host detection done", "duration", time.Since(startTime))

	var hosts []HostDetectionHostResultMessage
	for _, result := range results {
		hosts = append(hosts, HostDetectionHostResultMessage{
			IP:       result.IP,
			Protocol: result.Protocol,
			Ports:    result.Ports,
		})
	}
	var resultMessage = HostDetectionResultMessage{
		ID:    message.ID,
		Hosts: hosts,
	}

	r.reportResult(queueHostDetectionResul, resultMessage)

}

func (r *Runner) handleServiceDetectionMessage(message ServiceDetectionMessage) {
	logger.Info("Received service detection task", "id", message.ID)

	r.wg.Execute(func() {
		var result *scan.Result
		var err error
		switch message.Protocol {
		case "tcp":
			_, result, err = r.tcpScanner.Scan(newTask(message.IP, message.Port, message.Protocol))
		case "udp":
			_, result, err = r.udpScanner.Scan(newTask(message.IP, message.Port, message.Protocol))
		default:
			logger.Error("Unknown protocol", "protocol", message.Protocol)
			return
		}
		if err != nil {
			logger.Error("Error scanning", "ip", message.IP, "port", message.Port, "protocol", message.Protocol, "error", err)
			return
		}

		var resultMessage = ServiceDetectionResultMessage{
			ID:   message.ID,
			IP:   message.IP,
			Port: message.Port,
			Service: ServiceDetectionServiceResultMessage{
				SSL: result.SSL,
				Certs: lo.Map(result.Certs, func(cert *x509.Certificate, i int) string {
					return base64.StdEncoding.EncodeToString(cert.Raw)
				}),
				Banner:     result.Banner,
				Service:    result.Service,
				Product:    result.Product,
				Version:    result.Version,
				Info:       result.Info,
				Hostname:   result.Hostname,
				OS:         result.OS,
				DeviceType: result.DeviceType,
				CEPs:       result.CEPs,
			},
		}

		r.reportResult(queueServiceDetectionResul, resultMessage)
	})
}

func (r *Runner) reportResult(queue string, message any) {
	var body, err = json.Marshal(message)
	if err != nil {
		logger.Error("Error marshalling message", "error", err)
		return
	}
	err = r.amqpCh.Publish(
		"",
		queue,
		false,
		false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
	if err != nil {
		logger.Error("Error publishing message", "error", err)
	}
}

func newTask(ip string, port int, protocol string) *types.Task {
	var task = &types.Task{
		IP:     ip,
		Port:   port,
		Ctx:    context.Background(),
		Logger: log.NewLogger("module", "scan", "scan.ip", ip, "scan.port", port, "scan.protocol", protocol),
	}
	return task
}

func handleConsumeMessage[T any](ch *amqp.Channel, queue string, handler func(T)) error {

	deliveries, err := ch.Consume(
		queue,
		"",
		true,
		false,
		false,
		false,
		nil,
	)

	if err != nil {
		return fmt.Errorf("consuming - %w", err)
	}
	go func() {

		for d := range deliveries {
			var message T
			e := json.Unmarshal(d.Body, &message)
			if e != nil {
				log.Root.Error("Error unmarshalling message - "+string(d.Body), "error", e)
				continue
			}
			handler(message)
		}

	}()

	return nil
}
