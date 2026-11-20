import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { createNote, deleteNote, listNotes, type Note } from './notes'
import { ApiError, onBlocked } from './security/api'
import { ChannelError, channelEnabled } from './security/channel'

type ChannelState = 'connecting' | 'ready' | 'error'

function describe(e: unknown): string {
  if (e instanceof ChannelError) return e.message
  if (e instanceof ApiError) return `요청이 거부되었습니다 (${e.status})`
  return '요청을 처리하지 못했습니다'
}

// 주의: dangerouslySetInnerHTML 을 쓰지 않는다. JSX 의 {값} 은 자동으로 이스케이프된다.
export default function App() {
  const [notes, setNotes] = useState<Note[]>([])
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const [state, setState] = useState<ChannelState>('connecting')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [blocked, setBlocked] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setNotes(await listNotes())
      setState('ready')
      setError('')
    } catch (e) {
      setState('error')
      setError(describe(e))
    }
  }, [])

  useEffect(() => {
    const stop = onBlocked(() => setBlocked(true))
    void refresh()
    return () => {
      stop()
    }
  }, [refresh])

  async function add(event: FormEvent) {
    event.preventDefault()
    if (!title.trim() || busy) return
    setBusy(true)
    try {
      await createNote(title.trim(), body)
      setTitle('')
      setBody('')
      await refresh()
    } catch (e) {
      setError(describe(e))
    } finally {
      setBusy(false)
    }
  }

  async function remove(id: number) {
    try {
      await deleteNote(id)
      await refresh()
    } catch (e) {
      setError(describe(e))
    }
  }

  if (blocked) {
    return (
      <div className="blocked">
        <div>
          <h1>접근이 차단되었습니다</h1>
          <p className="muted">
            비정상적인 사용 환경이 감지되어 세션이 종료되었습니다. 개발자 도구를 닫고 새로고침해 주세요.
          </p>
        </div>
      </div>
    )
  }

  return (
    <main>
      <h1>__PROJECT_NAME__</h1>
      <p className="muted">
        보안 채널:{' '}
        {state === 'connecting' && <span className="status">연결 중…</span>}
        {state === 'ready' && (
          <span className="status ok">{channelEnabled ? '서명 + 암호화' : '꺼짐 (개발 모드)'}</span>
        )}
        {state === 'error' && <span className="status error">오류</span>}
      </p>
      {error && <p className="error">{error}</p>}

      <section className="panel">
        <form onSubmit={add}>
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            maxLength={100}
            placeholder="제목"
            aria-label="제목"
            required
          />
          <textarea
            value={body}
            onChange={(e) => setBody(e.target.value)}
            maxLength={4000}
            placeholder="내용"
            aria-label="내용"
          />
          <button type="submit" disabled={busy}>
            추가
          </button>
        </form>
      </section>

      <section className="panel">
        {notes.length === 0 ? (
          <p className="muted">아직 노트가 없습니다.</p>
        ) : (
          <ul className="notes">
            {notes.map((note) => (
              <li key={note.id}>
                <div>
                  <strong>{note.title}</strong>
                  <p>{note.body}</p>
                </div>
                <button type="button" className="ghost" onClick={() => void remove(note.id)}>
                  삭제
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  )
}
