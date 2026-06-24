import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Upload, Loader2, AlertCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import { analyzeThreat, analyzeFile, getAnalyses } from '../api/client'

const SAMPLE_INPUTS = [
  {
    label: 'Phishing Campaign',
    text: 'A phishing campaign targets finance users.\nDomain: secure-login-update.com\nIP: 185.199.108.153\nExploited Vulnerability: CVE-2023-3519\nAttack Goal: Credential Theft',
  },
  {
    label: 'Ransomware IOCs',
    text: 'IOC Report: LockBit 3.0\nC2 Server: 45.33.32.156\nPayload Hash: 5d41402abc4b2a76b9719d911017c592\nDrop Domain: update-service-cdn.com\nExploit: CVE-2024-21887',
  },
  {
    label: 'CVE Advisory',
    text: 'CVE-2024-53677',
  },
  {
    label: 'Low Risk Check',
    text: 'Investigate domain: marketing-analytics-tracker.com',
  },
]

export default function Dashboard() {
  const navigate = useNavigate()
  const [content, setContent] = useState('')
  const [inputType, setInputType] = useState('text')
  const [loading, setLoading] = useState(false)
  const [recentAnalyses, setRecentAnalyses] = useState([])
  const [options, setOptions] = useState({
    mitre_mapping: true,
    generate_rules: true,
    risk_scoring: true,
  })

  useEffect(() => {
    loadRecent()
  }, [])

  async function loadRecent() {
    try {
      const data = await getAnalyses(1, 5)
      setRecentAnalyses(data.analyses || [])
    } catch (e) {
      // Silently fail for history
    }
  }

  async function handleAnalyze(e) {
    e.preventDefault()
    if (!content.trim()) {
      toast.error('Please enter threat data to analyze')
      return
    }

    setLoading(true)
    try {
      const result = await analyzeThreat(content, inputType, options)
      toast.success('Analysis complete!')
      navigate(`/analysis/${result.analysis_id}`, { state: { result } })
    } catch (err) {
      const msg = err.response?.data?.detail || 'Analysis failed. Check backend connection.'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  async function handleFileUpload(e) {
    const file = e.target.files?.[0]
    if (!file) return

    const allowed = ['pdf', 'doc', 'docx', 'txt', 'csv', 'json']
    const ext = file.name.split('.').pop()?.toLowerCase()
    if (!allowed.includes(ext)) {
      toast.error(`Unsupported file type. Allowed: ${allowed.join(', ')}`)
      return
    }

    setLoading(true)
    try {
      const result = await analyzeFile(file, options)
      toast.success('File analysis complete!')
      navigate(`/analysis/${result.analysis_id}`, { state: { result } })
    } catch (err) {
      const msg = err.response?.data?.detail || 'File analysis failed.'
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  const riskLevelColor = {
    critical: 'text-red-400 bg-red-500/10',
    high: 'text-orange-400 bg-orange-500/10',
    medium: 'text-yellow-400 bg-yellow-500/10',
    low: 'text-green-400 bg-green-500/10',
  }

  return (
    <div className="space-y-6">
      {/* Input Form */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <h2 className="text-lg font-semibold text-slate-100 mb-4 flex items-center gap-2">
          <Search className="w-5 h-5 text-cyan-400" />
          Analyze a Threat
        </h2>

        <form onSubmit={handleAnalyze} className="space-y-4">
          {/* Input type selector */}
          <div className="flex gap-2 flex-wrap">
            {['text', 'cve', 'url'].map(type => (
              <button
                key={type}
                type="button"
                onClick={() => setInputType(type)}
                className={`px-3 py-1.5 rounded-lg text-sm transition-colors ${
                  inputType === type
                    ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40'
                    : 'bg-slate-800 text-slate-400 border border-slate-700 hover:border-slate-600'
                }`}
              >
                {type.toUpperCase()}
              </button>
            ))}
          </div>

          {/* Text area */}
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Paste threat report, enter CVE ID, or describe the threat here..."
            className="w-full h-36 px-4 py-3 bg-slate-950 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 resize-none"
          />

          {/* Quick fill samples */}
          <div className="flex gap-2 flex-wrap">
            <span className="text-xs text-slate-500">Quick fill:</span>
            {SAMPLE_INPUTS.map(s => (
              <button
                key={s.label}
                type="button"
                onClick={() => setContent(s.text)}
                className="text-xs px-2 py-1 rounded bg-slate-800 text-slate-400 hover:text-cyan-400 hover:bg-slate-700 transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>

          {/* Options */}
          <div className="flex gap-4 flex-wrap">
            {[
              { key: 'mitre_mapping', label: 'MITRE Mapping' },
              { key: 'risk_scoring', label: 'Risk Score' },
              { key: 'generate_rules', label: 'Sigma Rules' },
            ].map(opt => (
              <label key={opt.key} className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={options[opt.key]}
                  onChange={(e) => setOptions({ ...options, [opt.key]: e.target.checked })}
                  className="rounded border-slate-600 bg-slate-800 text-cyan-500 focus:ring-cyan-500/20"
                />
                {opt.label}
              </label>
            ))}
          </div>

          {/* Actions */}
          <div className="flex gap-3">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-2 px-5 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm font-medium rounded-lg transition-colors"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Analyze Threat
                </>
              )}
            </button>

            <label className="flex items-center gap-2 px-4 py-2.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded-lg cursor-pointer transition-colors border border-slate-700">
              <Upload className="w-4 h-4" />
              Upload File
              <input
                type="file"
                accept=".pdf,.doc,.docx,.txt,.csv,.json"
                onChange={handleFileUpload}
                className="hidden"
                disabled={loading}
              />
            </label>
          </div>
        </form>
      </div>

      {/* Recent Analyses */}
      {recentAnalyses.length > 0 && (
        <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-slate-200">Recent Analyses</h3>
          </div>
          <div className="divide-y divide-slate-800/50">
            {recentAnalyses.map(a => (
              <button
                key={a.analysis_id}
                onClick={() => navigate(`/analysis/${a.analysis_id}`)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-800/30 transition-colors text-left"
              >
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono text-slate-400">{a.analysis_id}</span>
                  <span className="text-sm text-slate-300 truncate max-w-xs">
                    {a.input_preview}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-sm font-bold text-slate-200">{a.risk_score}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full font-medium uppercase ${riskLevelColor[a.risk_level] || 'text-slate-400'}`}>
                    {a.risk_level}
                  </span>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Loading overlay */}
      {loading && (
        <div className="fixed inset-0 bg-slate-950/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-8 flex flex-col items-center gap-4">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin" />
            <div className="text-center">
              <p className="text-slate-200 font-medium">Analyzing Threat Data</p>
              <p className="text-slate-400 text-sm mt-1">Extracting IOCs, enriching, mapping to MITRE ATT&CK...</p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
