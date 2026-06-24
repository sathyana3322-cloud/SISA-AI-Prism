import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

const FACTOR_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#06b6d4', '#8b5cf6']

export default function RiskFactors({ factors }) {
  if (!factors || factors.length === 0) return null

  const data = factors.map((f, idx) => ({
    name: f.factor.length > 30 ? f.factor.slice(0, 30) + '...' : f.factor,
    fullName: f.factor,
    score: f.score,
  }))

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800">
        <h3 className="text-sm font-semibold text-slate-200">Risk Factor Breakdown</h3>
      </div>
      <div className="p-4">
        <ResponsiveContainer width="100%" height={factors.length * 40 + 20}>
          <BarChart data={data} layout="vertical" margin={{ left: 10, right: 20, top: 5, bottom: 5 }}>
            <XAxis type="number" domain={[0, 35]} tick={{ fill: '#94a3b8', fontSize: 11 }} />
            <YAxis
              type="category"
              dataKey="name"
              width={180}
              tick={{ fill: '#cbd5e1', fontSize: 11 }}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload?.[0]) {
                  return (
                    <div className="bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs">
                      <p className="text-slate-200">{payload[0].payload.fullName}</p>
                      <p className="text-cyan-400 font-bold">+{payload[0].value} points</p>
                    </div>
                  )
                }
                return null
              }}
            />
            <Bar dataKey="score" radius={[0, 4, 4, 0]}>
              {data.map((_, idx) => (
                <Cell key={idx} fill={FACTOR_COLORS[idx % FACTOR_COLORS.length]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
