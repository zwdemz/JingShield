package protection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"jingshield/internal/model"
	"jingshield/internal/protection/detector"
	"jingshield/internal/protection/reqctx"
)

type behaviorResultDetector struct{ result *detector.Result }

func (d behaviorResultDetector) Name() string { return "test" }
func (d behaviorResultDetector) Check(context.Context, *reqctx.RequestContext) *detector.Result {
	return d.result
}

type behaviorTestLocator struct{}

func (behaviorTestLocator) Lookup(string) string { return "test" }
func (behaviorTestLocator) Available() bool      { return true }

func TestBehaviorObservationContinuesWithoutBlockingOr403Audit(t *testing.T) {
	for _, observe := range []bool{true, false} {
		t.Run(map[bool]string{true: "observe", false: "block"}[observe], func(t *testing.T) {
			engine := &Engine{
				scanner: behaviorResultDetector{&detector.Result{Detected: true, ObserveOnly: observe, AttackType: model.AttackTypeScanner, Detail: "test"}},
				locator: behaviorTestLocator{},
				audit:   &auditWriter{access: make(chan *model.AccessLog, 1), attack: make(chan *model.AttackLog, 1)},
			}
			request := httptest.NewRequest("GET", "https://nas.example/.env", nil)
			request.Header.Set("Authorization", "Bearer should-not-be-recorded")
			requestContext := &reqctx.RequestContext{R: request, IP: "192.0.2.1", Header: request.Header, Method: request.Method, URI: request.RequestURI}
			decision := engine.evaluateBehavior(context.Background(), requestContext)
			if observe {
				if decision != nil || len(engine.audit.access) != 0 {
					t.Fatal("observation ended evaluation or wrote a blocked-access record")
				}
			} else if decision == nil || decision.Action != DecisionBlock || decision.StatusCode != http.StatusForbidden {
				t.Fatalf("blocking detector did not produce a 403: %+v", decision)
			}
			if len(engine.audit.attack) != 1 {
				t.Fatal("behavior detection was not audited")
			}
			attack := <-engine.audit.attack
			expectedStatus := 1
			if observe {
				expectedStatus = 2
			}
			if attack.Status != expectedStatus || attack.AttackType != model.AttackTypeScanner {
				t.Fatalf("incorrect behavior audit classification: %+v", attack)
			}
		})
	}
}
