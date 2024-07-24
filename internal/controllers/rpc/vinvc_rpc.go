package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/DIMO-Network/attestation-api/pkg/grpc"
	"github.com/DIMO-Network/attestation-api/pkg/verifiable"
	"golang.org/x/sync/errgroup"
)

type Server struct {
	ctrl vinCtrl
}

type vinCtrl interface {
	createVIN(ctx context.Context, tokenId uint32, force bool) error
}

func (s *Server) BatchCreateVINVC(ctx context.Context, req *grpc.BatchCreateVINVCRequest) (*grpc.BatchCreateVINVCResponse, error) {
	group, egCtx := errgroup.WithContext(ctx)
	group.SetLimit(25)
	resp := grpc.BatchCreateVINVCResponse{}
	var mtx sync.Mutex
	for _, tokenId := range req.GetTokenIds() {
		group.Go(func() error {
			result := &grpc.VINVCResult{
				TokenId: tokenId,
			}

			mtx.Lock()
			resp.Results = append(resp.Results, result)
			mtx.Unlock()

			err := s.ctrl.createVIN(egCtx, tokenId, req.GetForce())
			if err != nil {
				errStr := fmt.Sprintf("failed to create VC: %s", err.Error())
				result.Error = &errStr
				return nil
			}
			var vc verifiable.VerificationControlDocument
			rawVC, err := json.Marshal(vc)
			if err != nil {
				errStr := fmt.Sprintf("failed to marashal VC: %s", err.Error())
				result.Error = &errStr
				return nil
			}
			result.RawVC = string(rawVC)
			return nil
		})
	}
	err := group.Wait()
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
