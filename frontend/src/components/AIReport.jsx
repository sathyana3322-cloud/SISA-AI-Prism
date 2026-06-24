import { Brain, AlertTriangle, Target, Zap, Shield, Eye } from 'lucide-react'

export default function AIReport({ report }) {
  if (!report) return null

  const sections = [
    { title: 'Threat Summary', content: report.summary, icon: Brain, type: 'text' },
    { title: 'Attack Scenario', content: report.attack_scenario, icon: Target, type: 'text' },
    { title: 'Business Impact', content: report.business_impact, icon: AlertTriangle, type: 'text' },
    { title: 'Immediate Actions', content: report.immediate_actions, icon: Zap, type: 'list' },
    { title: 'Long-term Remediation', content: report.long_term_remediation, icon: Shield, type: 'list' },
    { title: 'Monitoring Recommendations', content: report.monitoring, icon: Eye, type: 'list' },
  ]

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center gap-2">
        <Brain className="w-4 h-4 text-purple-400" />
        <h3 className="text-sm font-semibold text-slate-200">AI Threat Intelligence Report</h3>
      </div>
      <div className="p-4 space-y-4">
        {sections.map(({ title, content, icon: Icon, type }) => {
          if (!content || (Array.isArray(content) && content.length === 0)) return null
          return (
            <div key={title} className="space-y-1">
              <div className="flex items-center gap-2">
                <Icon className="w-4 h-4 text-cyan-400" />
                <h4 className="text-sm font-semibold text-slate-300">{title}</h4>
              </div>
              {type === 'text' ? (
                <p className="text-sm text-slate-400 leading-relaxed pl-6">{content}</p>
              ) : (
                <ul className="text-sm text-slate-400 pl-6 space-y-1">
                  {content.map((item, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="text-cyan-400 mt-1">•</span>
                      {item}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
