package pom

// // GenerateKeyControlDocument generates a new control document for sharing public keys.
// func (s *Service) GenerateKeyControlDocument() (json.RawMessage, error) {
// 	keyDoc, err := s.issuer.CreateKeyControlDoc()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create key control document: %w", err)
// 	}
// 	return keyDoc, nil
// }

// // GenerateJSONLDDocument generates a new JSON-LD document.
// func (s *Service) GenerateJSONLDDocument() (json.RawMessage, error) {
// 	jsonLDDoc, err := s.issuer.CreateJSONLDDoc()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create JSON-LD document: %w", err)
// 	}
// 	return jsonLDDoc, nil
// }

// // GenerateVocabDocument generates a new vocabulary document.
// func (s *Service) GenerateVocabDocument() (json.RawMessage, error) {
// 	vocabDoc, err := s.issuer.CreateVocabWebpage()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create vocabulary document: %w", err)
// 	}
// 	return vocabDoc, nil
// }

// // GenerateStatusVC generates a new status VC.
// func (s *Service) GenerateStatusVC(tokenID uint32) (json.RawMessage, error) {
// 	vcData, err := s.issuer.CreateBitstringStatusListVC(tokenID, false)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create Status VC: %w", err)
// 	}
// 	return vcData, nil
// }
