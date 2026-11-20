/** 예제 리소스(notes) 호출. 실제 프로젝트의 API 모듈로 교체한다. */
import { api } from './security/api'

export interface Note {
  id: number
  title: string
  body: string
  created_at: string
}

export function listNotes(limit = 50): Promise<Note[]> {
  return api<Note[]>('GET', `/api/notes?limit=${encodeURIComponent(limit)}`)
}

export function createNote(title: string, body: string): Promise<Note> {
  return api<Note>('POST', '/api/notes', { title, body })
}

export function deleteNote(id: number): Promise<void> {
  return api<void>('DELETE', `/api/notes/${encodeURIComponent(id)}`)
}
