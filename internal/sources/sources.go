package sources

import "github.com/ethereum/go-ethereum/common"

var (
	MacaronOldFpSource = "macaron/fingerprint"
	AutoPiSource       = common.HexToAddress("0x5e31bBc786D7bEd95216383787deA1ab0f1c1897")
	RuptelaSource      = common.HexToAddress("0xF26421509Efe92861a587482100c6d728aBf1CD0")
	HashDogSource      = common.HexToAddress("0x4c674ddE8189aEF6e3b58F5a36d7438b2b1f6Bc2")
	SmartCarSource     = common.HexToAddress("0xcd445F4c6bDAD32b68a2939b912150Fe3C88803E")
	TeslaSource        = common.HexToAddress("0xc4035Fecb1cc906130423EF05f9C20977F643722")
	DINCSource         = common.HexToAddress("0x4F098Ea7cAd393365b4d251Dd109e791e6190239")
	SyntheticOldSource = "synthetic/device/fingerprint"
)

// AddrEqualString compares a common.Address with a string and returns true if they are equal.
func AddrEqualString(a common.Address, b string) bool {
	return common.IsHexAddress(b) && a.Cmp(common.HexToAddress(b)) == 0
}
