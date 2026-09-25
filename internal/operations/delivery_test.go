package operations

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"jingshield/internal/model"
)

func TestOneRequestExportsObservationAndEnforcementSeparately(t *testing.T) {
	service, memory := enabledService(t)
	entry := &model.AttackLog{EventID: "same-request", IP: "192.0.2.1", AttackType: "scanner", Status: 2}
	if err := service.Enqueue(context.Background(), entry); err != nil {
		t.Fatal(err)
	}
	entry.AttackType, entry.Status = "sql", 1
	for attempt := 0; attempt < 2; attempt++ {
		if err := service.Enqueue(context.Background(), entry); err != nil {
			t.Fatal(err)
		}
	}
	if len(memory.queue) != 2 {
		t.Fatalf("expected two independent decisions, got %d", len(memory.queue))
	}
	observed, blocked := memory.queue[0].Event, memory.queue[1].Event
	if observed.ID != entry.EventID || blocked.ID != entry.EventID || len(observed.DeliveryID) != 64 || observed.DeliveryID == blocked.DeliveryID || observed.Action != "observed" || blocked.Action != "blocked" {
		t.Fatal("request correlation or decision identity lost")
	}
	if (Event{ID: "legacy"}).deliveryKey() != "legacy" {
		t.Fatal("legacy queued payload became incompatible")
	}
}

func TestPeerExpiryLimitPreventsEnforcement(t *testing.T) {
	for _, limit := range []int{-1, 2147483, 31536001} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			service, memory := linkedService(t)
			posts := 0
			service.clientFactory = func(LinkageConfig) peerClient {
				return fakeClient(func(request *http.Request) (*http.Response, error) {
					if request.Method != http.MethodGet {
						posts++
					}
					return jsonResponse(Capabilities{Protocol: Protocol, DeviceType: "waf", Capabilities: []string{"block-batch"}, MaxBatchSize: 500, MaxExpireSeconds: limit}), nil
				})
			}
			_, err := service.BlockPeer(context.Background(), BlockRequest{IPs: []string{"192.0.2.1"}, Reason: "expiry test", ExpireSeconds: 2147484})
			if err == nil || posts != 0 || len(memory.audits) != 0 {
				t.Fatal("invalid or excessive expiry reached remote enforcement")
			}
		})
	}
}
