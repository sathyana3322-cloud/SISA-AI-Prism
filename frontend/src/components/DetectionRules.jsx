import { useState } from 'react'
import { Code, Copy, Check } from 'lucide-react'
import toast from 'react-hot-toast'

export default function DetectionRules({ rules }) {
  const [activeTab, setActiveTab] = useState('sigma')
  const [copied, setCopied] = useState(false)

  if (!rules) return null

  const tabs = [
    { id: 'sigma', label: 'Sigma', content: rules.sigma },
    { id: 'yara', label: 'YARA', content: rules.yara },
  ].filter(t => t.content)

  const handleCopy = () => {
    const content = tabs.find(t => t.id === activeTab)?.content
    if (content) {
      navigator.clipboard.writeText(content)
      setCopied(true)
      toast.success('Copied to clipboard!')
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Code className="w-4 h-4 text-green-400" />
          <h3 className="text-sm font-semibold text-slate-200">Detection Rules</h3>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1 px-2 py-1 rounded text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
        >
          {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied!' : 'Copy'}
        </button>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-800">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-cyan-400 border-b-2 border-cyan-400 bg-slate-800/50'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4">
        <pre className="text-xs text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap bg-slate-950 p-3 rounded-lg border border-slate-800">
          {tabs.find(t => t.id === activeTab)?.content || 'No rule generated'}
        </pre>
      </div>
    </div>
  )
}
