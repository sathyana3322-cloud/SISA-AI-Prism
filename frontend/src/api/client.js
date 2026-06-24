import axios from 'axios'

const API_BASE = import.meta.env.VITE_API_URL || ''

const client = axios.create({
  baseURL: API_BASE,
  timeout: 120000, // 2 minutes for AI processing
})

export async function analyzeThreat(content, inputType = 'text', options = {}) {
  const response = await client.post('/api/analyze-threat', {
    input_type: inputType,
    content,
    options: {
      mitre_mapping: true,
      generate_rules: true,
      risk_scoring: true,
      ...options,
    },
  })
  return response.data
}

export async function analyzeFile(file, options = {}) {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('options', JSON.stringify({
    mitre_mapping: true,
    generate_rules: true,
    risk_scoring: true,
    ...options,
  }))
  const response = await client.post('/api/analyze-threat/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return response.data
}

export async function getAnalyses(page = 1, pageSize = 20) {
  const response = await client.get(`/api/analyses?page=${page}&pageSize=${pageSize}`)
  return response.data
}

export async function getAnalysis(analysisId) {
  const response = await client.get(`/api/analyses/${analysisId}`)
  return response.data
}

export async function healthCheck() {
  const response = await client.get('/health')
  return response.data
}
