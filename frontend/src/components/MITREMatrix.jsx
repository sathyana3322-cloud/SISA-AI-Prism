import { Shield } from 'lucide-react'

const TACTIC_COLORS = {
  'Initial Access': 'bg-red-500/20 border-red-500/40 text-red-300',
  'Execution': 'bg-orange-500/20 border-orange-500/40 text-orange-300',
  'Persistence': 'bg-yellow-500/20 border-yellow-500/40 text-yellow-300',
  'Privilege Escalation': 'bg-amber-500/20 border-amber-500/40 text-amber-300',
  'Defense Evasion': 'bg-lime-500/20 border-lime-500/40 text-lime-300',
  'Credential Access': 'bg-purple-500/20 border-purple-500/40 text-purple-300',
  'Discovery': 'bg-blue-500/20 border-blue-500/40 text-blue-300',
  'Lateral Movement': 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300',
  'Collection': 'bg-teal-500/20 border-teal-500/40 text-teal-300',
  'Exfiltration': 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300',
  'Command and Control': 'bg-violet-500/20 border-violet-500/40 text-violet-300',
  'Impact': 'bg-rose-500/20 border-rose-500/40 text-rose-300',
}

const CONFIDENCE_BADGE = {
  high: 'bg-green-500/20 text-green-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-slate-500/20 text-slate-400',
}

export default function MITREMatrix({ mappings }) {
  if (!mappings || mappings.length === 0) return null

  // Group by tactic
  const grouped = {}
  mappings.forEach(m => {
    if (!grouped[m.tactic]) grouped[m.tactic] = []
    grouped[m.tactic].push(m)
  })

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
        <Shield className="w-4 h-4 text-cyan-400" />
        <h3 className="text-sm font-semibold text-slate-200">
          MITRE ATT&CK Mapping ({mappings.length} techniques)
        </h3>
      </div>

      {/* Attack Chain Visualization */}
      <div className="px-4 py-3 border-b border-slate-800/50">
        <div className="flex items-center gap-2 overflow-x-auto pb-2">
          {Object.keys(grouped).map((tactic, idx) => (
            <div key={tactic} className="flex items-center gap-2 shrink-0">
              <div className={`px-3 py-1.5 rounded-lg border text-xs font-medium ${TACTIC_COLORS[tactic] || 'bg-slate-500/20 border-slate-500/40 text-slate-300'}`}>
                {tactic}
              </div>
              {idx < Object.keys(grouped).length - 1 && (
                <span className="text-slate-600">→</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Technique Details */}
      <div className="p-4">
        <div className="grid gap-2">
          {mappings.map((m, idx) => (
            <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-slate-800/50 hover:bg-slate-800">
              <div className="flex items-center gap-3">
                <span className="text-xs font-mono text-cyan-400 w-20">{m.id}</span>
                <span className="text-sm text-slate-200">{m.technique}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs px-2 py-0.5 rounded ${TACTIC_COLORS[m.tactic] || 'bg-slate-600 text-slate-300'}`}>
                  {m.tactic}
                </span>
                {m.confidence && (
                  <span className={`text-xs px-2 py-0.5 rounded ${CONFIDENCE_BADGE[m.confidence] || CONFIDENCE_BADGE.medium}`}>
                    {m.confidence}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
