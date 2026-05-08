package ip_metadata

import "cdua-org/ReconSR/modules/utils/ripestat"

var (
	txtQueryFunc      = performTXTQuery
	ptrQueryFunc      = performPTRQuery
	aQueryFunc        = performAQuery
	ripestatQueryFunc = ripestat.Query
)
