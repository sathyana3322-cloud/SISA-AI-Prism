import { useEffect, useState } from 'react'

const RISK_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

export default function RiskGauge({ score, level }) {
  const [animatedScore, setAnimatedScore] = useState(0)

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 100)
    return () => clearTimeout(timer)
  }, [score])

  const color = RISK_COLORS[level] || '#64748b'
  const rotation = (animatedScore / 100) * 180 - 90 // -90 to 90 degrees

  return (
    <div className="flex flex-col items-center">
      {/* Gauge */}
      <div className="relative w-48 h-24 overflow-hidden">
        {/* Background arc */}
        <div className="absolute inset-0 rounded-t-full bg-gradient-to-r from-green-500 via-yellow-500 via-orange-500 to-red-500 opacity-20" />
        <div className="absolute inset-[6px] rounded-t-full bg-slate-900" />

        {/* Needle */}
        <div
          className="absolute bottom-0 left-1/2 origin-bottom transition-transform duration-1000 ease-out"
          style={{ transform: `translateX(-50%) rotate(${rotation}deg)` }}
        >
          <div className="w-0.5 h-20 bg-white rounded-full" />
          <div className="w-3 h-3 bg-white rounded-full -mt-1 -ml-[5px]" />
        </div>
      </div>

      {/* Score display */}
      <div className="mt-2 text-center">
        <span className="text-4xl font-bold" style={{ color }}>
          {animatedScore}
        </span>
        <span className="text-slate-400 text-lg">/100</span>
      </div>
      <span
        className="mt-1 text-sm font-semibold uppercase tracking-wider px-3 py-1 rounded-full"
        style={{ color, backgroundColor: `${color}20` }}
      >
        {level}
      </span>
    </div>
  )
}
