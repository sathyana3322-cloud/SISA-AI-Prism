import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import AnalysisResult from './pages/AnalysisResult'
import History from './pages/History'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="analysis/:id" element={<AnalysisResult />} />
        <Route path="history" element={<History />} />
      </Route>
    </Routes>
  )
}

export default App
