package evaluation

import (
	"key_recovery/modules/configuration"
)

func Evaluate(cfg *configuration.SimulationConfig, mainDir string, evalType int,
	varyingParameter int) {
	switch {
	case evalType%3 == 0:
		switch varyingParameter {
		case 1:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson(cfg, mainDir)
		case 2:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtPerPerson(cfg, mainDir)
		case 3:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPU(cfg, mainDir)
		case 4:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtPerPersonCPU(cfg, mainDir)
		case 5:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(cfg, mainDir)
		case 6:
			// EvaluateWCBasicHashedSecretRecovery(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExt(cfg, mainDir)
		case 7:
			// EvaluateWCBasicHashedSecretRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
		case 8:
			// EvaluateWCBasicHashedSecretRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExt(cfg, mainDir)
		case 9:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		case 10:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		case 11:
			EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
		case 12:
			EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
		case 13:
			EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
		case 14:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4(cfg, mainDir)
		case 15:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4CPU(cfg, mainDir)
		case 16:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson5(cfg, mainDir)
		case 17:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson5CPU(cfg, mainDir)
		case 18:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson6(cfg, mainDir)
		case 19:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingHints(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson6CPU(cfg, mainDir)
		// case 20:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecovery(cfg, mainDir)
		// case 21:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
		// case 22:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
		// case 23:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
		// case 24:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
		// case 25:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingHints(cfg, mainDir)
		case 26:
			// BenchmarkBasicHashedSecretRecoveryAlternate(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 401, 500)
		case 27:
			// EvaluateBasicHashedSecretRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 501, 600)
		case 28:
			// EvaluateBasicHashedSecretRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 601, 700)
		case 29:
			// EvaluateBasicHashedSecretRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 701, 800)
		case 30:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 801, 850)
		case 31:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 851, 900)
		case 32:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 901, 950)
		case 33:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPULimits(cfg, mainDir, 951, 1000)
		case 34:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 401, 500)
		case 35:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecovery(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 501, 600)
		case 36:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 601, 700)
		case 37:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 701, 800)
		case 38:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 801, 900)
		case 39:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 901, 950)
		case 40:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSharesPerPerson(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonLimits(cfg, mainDir, 951, 1000)
		case 41:
			EvaluateOverallPacketSize(cfg, mainDir)
		case 42:
			// EvaluateBCTwoLayeredAdditiveOptUsedIndisRecovery(cfg, mainDir)
			// EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			// EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			// EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			// EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
			// EvaluateBCBasicHashedSecretRecovery(cfg, mainDir)
			// EvaluateBCBasicHashedSecretRecoveryVaryingThreshold(cfg, mainDir)
			// EvaluateBCBasicHashedSecretRecoveryVaryingTrustees(cfg, mainDir)
			// EvaluateBCTwoLayeredThresholdedOptUsedIndisRecovery(cfg, mainDir)
			// EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThreshold(cfg, mainDir)
			// EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrustees(cfg, mainDir)
			// EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingAT(cfg, mainDir)
			// EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSS(cfg, mainDir)
		case 43:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtParam(cfg, mainDir, 7)
		case 44:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryLargeAnon(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtParam(cfg, mainDir, 8)
		case 45:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryLargeAnon(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtParam(cfg, mainDir, 9)
		case 46:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryExponential(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtParam(cfg, mainDir, 11)
		case 47:
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryExponential(cfg, mainDir)
		case 48:
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryExponential(cfg, mainDir)
		default:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecovery(cfg, mainDir)
		}
	case evalType%3 == 1:
		switch varyingParameter {
		case 1:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVAnon(cfg, mainDir)
		case 2:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVTh(cfg, mainDir)
		case 3:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVTr(cfg, mainDir)
		case 4:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVAT(cfg, mainDir)
		case 5:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVSS(cfg, mainDir)
		case 6:
			EvaluateGetBaselineProbabilityCDFVTh(cfg, mainDir)
		case 7:
			EvaluateGetBaselineProbabilityCDFVTr(cfg, mainDir)
		case 8:
			EvaluateGetBaselineProbabilityCDFVAnon(cfg, mainDir)
		case 9:
			EvaluateGetThresholdedProbabilityFixedThTotalCDFVAnon(cfg, mainDir)
		case 10:
			EvaluateGetThresholdedProbabilityFixedThTotalCDFVTh(cfg, mainDir)
		case 11:
			EvaluateGetThresholdedProbabilityFixedThTotalCDFVTr(cfg, mainDir)
		case 12:
			EvaluateGetThresholdedProbabilityFixedThTotalCDFVAT(cfg, mainDir)
		case 13:
			EvaluateGetThresholdedProbabilityFixedThTotalCDFVSS(cfg, mainDir)
		case 14:
			EvaluateGetHintedTProbabilityFixedThTotalCDFVAnon(cfg, mainDir)
		case 15:
			EvaluateGetHintedTProbabilityFixedThTotalCDFVTh(cfg, mainDir)
		case 16:
			EvaluateGetHintedTProbabilityFixedThTotalCDFVTr(cfg, mainDir)
		case 17:
			EvaluateGetHintedTProbabilityFixedThTotalCDFVAT(cfg, mainDir)
		case 18:
			EvaluateGetHintedTProbabilityFixedThTotalCDFVSS(cfg, mainDir)
		case 19:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVSPP(cfg, mainDir)
		case 20:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVAnonExponential(cfg, mainDir)
		case 21:
			EvaluateGetAdditiveExpectedProbabilityFixedThTotalCDFVAnon(cfg, mainDir)
		case 22:
			EvaluateGetAdditiveExpectedProbabilityFixedThTotalCDFVAnonExponential(cfg, mainDir)
		case 23:
			EvaluateTrusteesExpectedProbability(cfg, mainDir)
		case 24:
			EvaluateExpectedProbability(cfg, mainDir)
		case 25:
			EvaluateGetAdditiveProbabilityFixedThNumwiseCDFVAnon(cfg, mainDir)
		case 26:
			EvaluateGetUserCompProbabilityCDFParallelized(cfg, mainDir)
		case 27:
			EvaluateGetAdvCompProbabilityCDFParallelized(cfg, mainDir)
		case 28:
			EvaluateNotCaughtProbability(cfg, mainDir)
		case 29:
			EvaluateObtainSecretProbability(cfg, mainDir)
		case 30:
			EvaluateGetAdditiveCompWBAdvObtProbabilityFixedThNumwise(cfg, mainDir)
		case 31:
			EvaluateGetAdditiveWBAdvObtProbabilityFixedThNumwise(cfg, mainDir)
		case 32:
			EvaluateGetCompWBAdvObtProbabilityCDFParallelized(cfg, mainDir)
		case 33:
			EvaluateGetWBAdvObtProbabilityCDFParallelized(cfg, mainDir)
		case 34:
			EvaluateGetCompWBAdvObtBaselineProbabilityCDF(cfg, mainDir)
		case 35:
			EvaluateGetWBAdvObtBaselineProbabilityCDF(cfg, mainDir)
		case 36:
			EvaluateGetCompWBAdvObtProbabilityCDFParallelizedAbs(cfg, mainDir)
		case 37:
			EvaluateGetCompWBAdvObtProbabilityCDFParallelizedSS(cfg, mainDir)
		default:
			EvaluateGetAdditiveProbabilityFixedThTotalCDFVAnon(cfg, mainDir)
		}
	case evalType%3 == 2:
		switch varyingParameter {
		case 1:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 1)
		case 2:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 2)
		case 3:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 3)
		case 4:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 4)
		case 5:
			// EvaluateWCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 5)
		case 6:
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 1)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 7)
		case 7:
			// EvaluateWCBasicHashedSecretRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 2)
		case 8:
			// EvaluateWCBasicHashedSecretRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 3)
		case 9:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 4)
		case 10:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 5)
		case 11:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryBinExtCPU(cfg, mainDir, 6)
		case 12:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT5BinExtCPU(cfg, mainDir)
		case 13:
			// EvaluateWCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT6BinExtCPU(cfg, mainDir)
		case 14:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 1)
		case 15:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 2)
		case 16:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 3)
		case 17:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 4)
		case 18:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 5)
		case 19:
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryVaryingHintsBinExt(cfg, mainDir)
		// case 20:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryBinExt(cfg, mainDir)
		// case 21:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
		// case 22:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		// case 23:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
		// case 24:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
		// case 25:
		// 	EvaluateTwoLayeredHintedShOptUsedIndisRecoveryVaryingHintsBinExt(cfg, mainDir)
		case 26:
			BenchmarkBasicHashedSecretRecoveryAlternateBinExt(cfg, mainDir)
		case 27:
			EvaluateBasicHashedSecretRecoveryBinExt(cfg, mainDir)
		case 28:
			// EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExtCPU(cfg, mainDir)
		case 29:
			// EvaluateBasicHashedSecretRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecoveryVaryingThresholdBinExtCPU(cfg, mainDir)
		case 30:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoverySecretSizeBinExtCPU(cfg, mainDir)
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(cfg, mainDir)
		case 31:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExtCPU(cfg, mainDir)
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
		case 32:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExtCPU(cfg, mainDir)
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		case 33:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingAT4BinExtCPU(cfg, mainDir)
		case 34:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExtCPU(cfg, mainDir)
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
		case 35:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 1)
		case 36:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 2)
		case 37:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 3)
		case 38:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 4)
		case 39:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExtCPU(cfg, mainDir, 5)
		case 40:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSharesPerPersonBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryBinExt(cfg, mainDir)
		case 41:
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryBinExt(cfg, mainDir)
		// case 41:
		// 	EvaluateOverallPacketSizeBinExt(cfg, mainDir)
		case 42:
		// 	EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredAdditiveOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
		// 	EvaluateBCBasicHashedSecretRecoveryBinExt(cfg, mainDir)
		// 	EvaluateBCBasicHashedSecretRecoveryVaryingThresholdBinExt(cfg, mainDir)
		// 	EvaluateBCBasicHashedSecretRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingThresholdBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingTrusteesBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingATBinExt(cfg, mainDir)
		// 	EvaluateBCTwoLayeredThresholdedOptUsedIndisRecoveryVaryingSSBinExt(cfg, mainDir)
		case 43:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryLargeAnonBinExt(cfg, mainDir)
			EvaluateTwoLayeredAdditiveOptUsedIndisRecovery(cfg, mainDir)
		case 44:
			// EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryLargeAnonBinExt(cfg, mainDir)
			EvaluateBasicHashedSecretRecovery(cfg, mainDir)
		case 45:
			// EvaluateTwoLayeredHintedTOptUsedIndisRecoveryLargeAnonBinExt(cfg, mainDir)
			EvaluateTwoLayeredThresholdedOptUsedIndisRecovery(cfg, mainDir)
		case 46:
			// EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryExponentialBinExt(cfg, mainDir)
			EvaluateTwoLayeredHintedTOptUsedIndisRecovery(cfg, mainDir)
		case 47:
			EvaluateTwoLayeredThresholdedOptUsedIndisRecoveryExponentialBinExt(cfg, mainDir)
		case 48:
			EvaluateTwoLayeredHintedTOptUsedIndisRecoveryExponentialBinExt(cfg, mainDir)
		case 49:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoverySecretSizeBinExt(cfg, mainDir)
		case 50:
			EvaluateOverallPacketSizeBinExt(cfg, mainDir)
		case 51:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson(cfg, mainDir)
		case 52:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4(cfg, mainDir)
		case 53:
			EvaluateBasicHashedSecretRecoveryBinExtPerPerson(cfg, mainDir)
		case 54:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPersonCPU(cfg, mainDir)
		case 55:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExtPerPerson4CPU(cfg, mainDir)
		case 56:
			EvaluateBasicHashedSecretRecoveryBinExtPerPersonCPU(cfg, mainDir)
		default:
			EvaluateTwoLayeredAdditiveOptUsedIndisRecoveryBinExt(cfg, mainDir)
		}
	}
}
