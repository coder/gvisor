// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forwarder_test

import (
	"os"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checker"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/test/e2e"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp/testing/context"
)

func TestForwarderSendMSSLessThanMTU(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		close(ch)
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do 3-way handshake.
	c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize})

	// Wait for connection to be available.
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	// Check that data gets properly segmented.
	e2e.CheckBrokenUpWrite(t, c, maxPayload)
}

func TestForwarderDoesNotRejectECNFlags(t *testing.T) {
	testCases := []struct {
		name  string
		flags header.TCPFlags
	}{
		{name: "non-setup ECN SYN w/ ECE", flags: header.TCPFlagEce},
		{name: "non-setup ECN SYN w/ CWR", flags: header.TCPFlagCwr},
		{name: "setup ECN SYN", flags: header.TCPFlagEce | header.TCPFlagCwr},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			const maxPayload = 100
			const mtu = 1200
			c := context.New(t, mtu)
			defer c.Cleanup()

			s := c.Stack()
			ch := make(chan tcpip.Error, 1)
			f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
				var err tcpip.Error
				c.EP, err = r.CreateEndpoint(&c.WQ)
				ch <- err
				close(ch)
				r.Complete(false)
			})
			s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

			// Do 3-way handshake.
			c.PassiveConnect(maxPayload, -1, header.TCPSynOptions{MSS: mtu - header.IPv4MinimumSize - header.TCPMinimumSize, Flags: tc.flags})

			// Wait for connection to be available.
			select {
			case err := <-ch:
				if err != nil {
					t.Fatalf("Error creating endpoint: %s", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("Timed out waiting for connection")
			}
		})
	}
}

func TestForwarderFailedConnect(t *testing.T) {
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		close(ch)
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Initiate a connection that will be forwarded by the Forwarder.
	// Send a SYN request.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	// Receive the SYN-ACK reply. Make sure MSS and other expected options
	// are present.
	v := c.GetPacket()
	defer v.Release()
	tcp := header.TCP(header.IPv4(v.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcp.SequenceNumber())

	tcpCheckers := []checker.TransportChecker{
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagAck | header.TCPFlagSyn),
		checker.TCPAckNum(uint32(iss) + 1),
	}
	checker.IPv4(t, v, checker.TCP(tcpCheckers...))

	// Now send an active RST to abort the handshake.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagRst,
		SeqNum:  iss + 1,
		RcvWnd:  0,
	})

	// Wait for connect to fail.
	select {
	case err := <-ch:
		if err == nil {
			t.Fatalf("endpoint creation should have failed")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection to fail")
	}
}

func TestForwarderReopenAfterTimeWait(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	// Buffered so the handler for either connection can send its result
	// without waiting on the test to catch up.
	ch := make(chan tcpip.Error, 2)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then immediately
	// close the resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	b := c.GetPacket()
	defer b.Release()
	tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	c.EP.Close()

	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	// Ack our FIN and send our own, which puts the forwarded endpoint into
	// TIME_WAIT once we ack it below.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// The 4-tuple is now in TIME_WAIT. Per RFC 1122, a new SYN with a
	// sequence number higher than anything seen on the old connection
	// should be allowed to reopen the connection. Since this stack only
	// has a tcp.Forwarder and no bound listening endpoint, the new SYN
	// must reach the forwarder just like a brand new connection would.
	newISS := iss.Add(3)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  newISS,
		RcvWnd:  30000,
	})

	b = c.GetPacket()
	defer b.Release()
	tcpHdr = header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())
	checker.IPv4(t, b, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
		checker.TCPAckNum(uint32(newISS)+1)))

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  newISS + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint for reopened connection: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for reopened connection")
	}
}

// TestForwarderTimeWaitSynAckKeepsTimeWait checks that a SYN-ACK in TIME_WAIT
// gets no reply and that TIME_WAIT still answers a FIN retransmit with an ACK.
func TestForwarderTimeWaitSynAckKeepsTimeWait(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then immediately
	// close the resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})

	b := c.GetPacket()
	defer b.Release()
	tcpHdr := header.TCP(header.IPv4(b.AsSlice()).Payload())
	c.IRS = seqnum.Value(tcpHdr.SequenceNumber())

	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})

	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}

	c.EP.Close()

	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+1)),
		checker.TCPAckNum(uint32(iss)+1),
		checker.TCPFlags(header.TCPFlagFin|header.TCPFlagAck)))

	// Ack our FIN and send our own, which puts the forwarded endpoint into
	// TIME_WAIT once we ack it below.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})

	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	// The 4-tuple is now in TIME_WAIT. A SYN-ACK with a sequence number
	// higher than anything seen on the old connection counts as a "new SYN"
	// in handleTimeWaitSegment, but it is not a reopen, so it must be
	// dropped without a reply rather than redelivered.
	newISS := iss.Add(3)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn | header.TCPFlagAck,
		SeqNum:  newISS,
		AckNum:  c.IRS.Add(100),
		RcvWnd:  30000,
	})
	c.CheckNoPacketTimeout("unexpected reply to a SYN-ACK in TIME_WAIT", 500*time.Millisecond)

	// TIME_WAIT still holds the 4-tuple: a FIN retransmit gets an ACK.
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})
	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPSeqNum(uint32(c.IRS+2)),
		checker.TCPAckNum(uint32(iss)+2),
		checker.TCPFlags(header.TCPFlagAck)))

	select {
	case err := <-ch:
		t.Fatalf("forwarder unexpectedly created an endpoint for a SYN-ACK: %s", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestForwarderDroppedStats(t *testing.T) {
	const maxPayload = 100
	const mtu = 1200
	c := context.New(t, mtu)
	defer c.Cleanup()

	const maxInFlight = 2
	iters := atomicbitops.FromInt64(maxInFlight)
	s := c.Stack()
	checkedStats := make(chan struct{})
	done := make(chan struct{})
	f := tcp.NewForwarder(s, 65536, maxInFlight, func(r *tcp.ForwarderRequest) {
		<-checkedStats
		// Complete all requests without doing anything
		r.Complete(false)
		if iter := iters.Add(-1); iter == 0 {
			close(done)
		}
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	for i := 0; i < maxInFlight+1; i++ {
		iss := seqnum.Value(context.TestInitialSequenceNumber + i)
		c.SendPacket(nil, &context.Headers{
			SrcPort: uint16(context.TestPort + i),
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  iss,
			RcvWnd:  30000,
		})
	}

	// Verify that we got one ignored packet.
	if curr := s.Stats().TCP.ForwardMaxInFlightDrop.Value(); curr != 1 {
		t.Errorf("Expected one dropped connection, but got %d", curr)
	}
	close(checkedStats)
	<-done
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	// Allow TCP async work to complete to avoid false reports of leaks.
	// TODO(gvisor.dev/issue/5940): Use fake clock in tests.
	time.Sleep(1 * time.Second)
	refs.DoLeakCheck()
	os.Exit(code)
}

// TestForwarderReopenAfterTimeWaitDuplicateSYN checks that a duplicate of the
// reopening SYN, queued behind it on the TIME_WAIT endpoint, gets no RST.
func TestForwarderReopenAfterTimeWaitDuplicateSYN(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 2)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then close the
	// resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})
	b := c.GetPacket()
	defer b.Release()
	c.IRS = seqnum.Value(header.TCP(header.IPv4(b.AsSlice()).Payload()).SequenceNumber())
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
	c.EP.Close()
	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin)))
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})
	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck)))

	// Queue the reopening SYN and a duplicate on the TIME_WAIT endpoint.
	newISS := iss.Add(3)
	s.Pause()
	for range 2 {
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  newISS,
			RcvWnd:  30000,
		})
	}
	s.Resume()

	b = c.GetPacket()
	defer b.Release()
	checker.IPv4(t, b, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
		checker.TCPAckNum(uint32(newISS)+1)))
	c.CheckNoPacketTimeout("unexpected packet after SYN-ACK for the reopening SYN", 500*time.Millisecond)
}

// TestForwarderTimeWaitDeclinedSYNGetsReset checks that a reopening SYN gets a
// RST when the default handler returns false for it.
func TestForwarderTimeWaitDeclinedSYNGetsReset(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 1)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	var decline atomicbitops.Bool
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		if decline.Load() {
			return false
		}
		return f.HandlePacket(id, pkt)
	})

	// Do a 3-way handshake through the forwarder and then close the
	// resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})
	b := c.GetPacket()
	defer b.Release()
	c.IRS = seqnum.Value(header.TCP(header.IPv4(b.AsSlice()).Payload()).SequenceNumber())
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
	c.EP.Close()
	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin)))
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})
	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck)))

	decline.Store(true)
	newISS := iss.Add(3)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  newISS,
		RcvWnd:  30000,
	})
	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagRst|header.TCPFlagAck),
		checker.TCPAckNum(uint32(newISS)+1)))
}

// TestForwarderReopenAfterTimeWaitStaleSYN checks that a SYN below the old
// RcvNxt, queued behind the reopening SYN, does not get the SYN-ACK.
func TestForwarderReopenAfterTimeWaitStaleSYN(t *testing.T) {
	c := context.New(t, e2e.DefaultMTU)
	defer c.Cleanup()

	s := c.Stack()
	ch := make(chan tcpip.Error, 2)
	f := tcp.NewForwarder(s, 65536, 10, func(r *tcp.ForwarderRequest) {
		var err tcpip.Error
		c.EP, err = r.CreateEndpoint(&c.WQ)
		ch <- err
		r.Complete(false)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, f.HandlePacket)

	// Do a 3-way handshake through the forwarder and then close the
	// resulting endpoint, so it settles into TIME_WAIT.
	iss := seqnum.Value(context.TestInitialSequenceNumber)
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagSyn,
		SeqNum:  iss,
		RcvWnd:  30000,
	})
	b := c.GetPacket()
	defer b.Release()
	c.IRS = seqnum.Value(header.TCP(header.IPv4(b.AsSlice()).Payload()).SequenceNumber())
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 1,
	})
	select {
	case err := <-ch:
		if err != nil {
			t.Fatalf("Error creating endpoint: %s", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for connection")
	}
	c.EP.Close()
	v := c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck|header.TCPFlagFin)))
	c.SendPacket(nil, &context.Headers{
		SrcPort: context.TestPort,
		DstPort: context.StackPort,
		Flags:   header.TCPFlagAck | header.TCPFlagFin,
		SeqNum:  iss + 1,
		AckNum:  c.IRS + 2,
	})
	v = c.GetPacket()
	defer v.Release()
	checker.IPv4(t, v, checker.TCP(checker.TCPFlags(header.TCPFlagAck)))

	// Queue the reopening SYN and then a SYN below the old RcvNxt (iss+2)
	// on the TIME_WAIT endpoint.
	newISS := iss.Add(3)
	s.Pause()
	for _, seq := range []seqnum.Value{newISS, iss} {
		c.SendPacket(nil, &context.Headers{
			SrcPort: context.TestPort,
			DstPort: context.StackPort,
			Flags:   header.TCPFlagSyn,
			SeqNum:  seq,
			RcvWnd:  30000,
		})
	}
	s.Resume()

	b = c.GetPacket()
	defer b.Release()
	checker.IPv4(t, b, checker.TCP(
		checker.SrcPort(context.StackPort),
		checker.DstPort(context.TestPort),
		checker.TCPFlags(header.TCPFlagSyn|header.TCPFlagAck),
		checker.TCPAckNum(uint32(newISS)+1)))
	c.CheckNoPacketTimeout("unexpected packet after SYN-ACK for the reopening SYN", 500*time.Millisecond)
}
