import { Globe, Server, Hash, Mail, Link, Bug } from 'lucide-react'

const IOC_ICONS = {
  domain: Globe,
  ipv4: Server,
  md5: Hash,
  sha1: Hash,
  sha256: Hash,
  email: Mail,
  url: Link,
  cve: Bug,
}

const REPUTATION_STYLES = {
  malicious: 'bg-red-500/10 text-red-400 border-red-500/30',
  suspicious: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
  critical: 'bg-red-500/10 text-red-400 border-red-500/30',
  clean: 'bg-green-500/10 text-green-400 border-green-500/30',
  unknown: 'bg-slate-500/10 text-slate-400 border-slate-500/30',
}

export default function IOCTable({ iocs }) {
  if (!iocs || iocs.length === 0) return null

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-4 py-3 border-b border-slate-800">
        <h3 className="text-sm font-semibold text-slate-200">
          Extracted IOCs ({iocs.length})
        </h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-800">
              <th className="px-4 py-2 text-left text-slate-400 font-medium">Type</th>
              <th className="px-4 py-2 text-left text-slate-400 font-medium">Value</th>
              <th className="px-4 py-2 text-left text-slate-400 font-medium">Reputation</th>
            </tr>
          </thead>
          <tbody>
            {iocs.map((ioc, idx) => {
              const Icon = IOC_ICONS[ioc.type] || Hash
              return (
                <tr key={idx} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-4 py-2">
                    <span className="flex items-center gap-2 text-slate-300">
                      <Icon className="w-4 h-4 text-cyan-400" />
                      {ioc.type.toUpperCase()}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-slate-200 break-all max-w-xs">
                    {ioc.value}
                    {ioc.cvss && (
                      <span className="ml-2 text-xs text-red-400">CVSS {ioc.cvss}</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs border ${REPUTATION_STYLES[ioc.reputation] || REPUTATION_STYLES.unknown}`}>
                      {ioc.reputation}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
