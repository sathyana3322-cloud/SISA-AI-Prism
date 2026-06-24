import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { History as HistoryIcon, ChevronLeft, ChevronRight } from 'lucide-react'
import { getAnalyses } from '../api/client'

const riskLevelColor = {
  critical: 'text-red-400 bg-red-500/10',
  high: 'text-orange-400 bg-orange-500/10',
  medium: 'text-yellow-400 bg-yellow-500/10',
  low: 'text-green-400 bg-green-500/10',
}

export default function History() {
  const navigate = useNavigate()
  const [analyses, setAnalyses] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(true)
  const pageSize = 20

  useEffect(() => {
    loadPage()
  }, [page])

  async function loadPage() {
    setLoading(true)
    try {
      const data = await getAnalyses(page, pageSize)
      setAnalyses(data.analyses || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error('Failed to load analyses:', e)
    } finally {
      setLoading(false)
    }
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <HistoryIcon className="w-5 h-5 text-cyan-400" />
        <h2 className="text-lg font-semibold text-slate-100">Analysis History</h2>
        <span className="text-sm text-slate-400">({total} total)</span>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-32">
          <div className="animate-spin w-6 h-6 border-2 border-cyan-400 border-t-transparent rounded-full" />
        </div>
      ) : analyses.length === 0 ? (
        <div className="text-center py-12 text-slate-400">
          <p>No analyses yet. Start by analyzing a threat on the dashboard.</p>
        </div>
      ) : (
        <>
          <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">ID</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Input</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Risk</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Level</th>
                  <th className="px-4 py-3 text-left text-slate-400 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map(a => (
                  <tr
                    key={a.analysis_id}
                    onClick={() => navigate(`/analysis/${a.analysis_id}`)}
                    className="border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3 font-mono text-xs text-cyan-400">{a.analysis_id}</td>
                    <td className="px-4 py-3 text-slate-300 truncate max-w-xs">{a.input_preview}</td>
                    <td className="px-4 py-3 font-bold text-slate-200">{a.risk_score}</td>
                    <td className="px-4 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium uppercase ${riskLevelColor[a.risk_level] || ''}`}>
                        {a.risk_level}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 text-xs">
                      {new Date(a.timestamp).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="p-2 rounded-lg bg-slate-800 text-slate-400 disabled:opacity-30 hover:bg-slate-700"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-sm text-slate-400">Page {page} of {totalPages}</span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="p-2 rounded-lg bg-slate-800 text-slate-400 disabled:opacity-30 hover:bg-slate-700"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
