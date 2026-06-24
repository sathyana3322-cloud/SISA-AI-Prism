import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { ArrowLeft, Clock } from 'lucide-react'
import { getAnalysis } from '../api/client'
import RiskGauge from '../components/RiskGauge'
import RiskFactors from '../components/RiskFactors'
import IOCTable from '../components/IOCTable'
import MITREMatrix from '../components/MITREMatrix'
import AIReport from '../components/AIReport'
import DetectionRules from '../components/DetectionRules'

export default function AnalysisResult() {
  const { id } = useParams()
  const location = useLocation()
  const navigate = useNavigate()
  const [result, setResult] = useState(location.state?.result || null)
  const [loading, setLoading] = useState(!result)

  useEffect(() => {
    if (!result && id) {
      setLoading(true)
      getAnalysis(id)
        .then(data => setResult(data))
        .catch(() => navigate('/'))
        .finally(() => setLoading(false))
    }
  }, [id, result, navigate])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin w-8 h-8 border-2 border-cyan-400 border-t-transparent rounded-full" />
      </div>
    )
  }

  if (!result) return null

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/')}
            className="p-2 rounded-lg hover:bg-slate-800 text-slate-400 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-lg font-bold text-slate-100">{result.analysis_id}</h1>
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Clock className="w-3 h-3" />
              {new Date(result.timestamp).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Risk Score + Factors */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 flex items-center justify-center">
          <RiskGauge score={result.risk_score} level={result.risk_level} />
        </div>
        <RiskFactors factors={result.risk_factors} />
      </div>

      {/* IOCs */}
      <IOCTable iocs={result.iocs} />

      {/* MITRE ATT&CK */}
      <MITREMatrix mappings={result.mitre_mapping} />

      {/* AI Report */}
      <AIReport report={result.ai_report} />

      {/* Detection Rules */}
      <DetectionRules rules={result.detection_rules} />
    </div>
  )
}
