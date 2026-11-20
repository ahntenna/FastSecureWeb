<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { createNote, deleteNote, listNotes, type Note } from './notes'
import { ApiError, onBlocked } from './security/api'
import { ChannelError, channelEnabled } from './security/channel'

// 주의: v-html 을 쓰지 않는다. {{ }} 보간은 자동으로 이스케이프된다.
const notes = ref<Note[]>([])
const title = ref('')
const body = ref('')
const state = ref<'connecting' | 'ready' | 'error'>('connecting')
const error = ref('')
const busy = ref(false)
const blocked = ref(false)

function describe(e: unknown): string {
  if (e instanceof ChannelError) return e.message
  if (e instanceof ApiError) return `요청이 거부되었습니다 (${e.status})`
  return '요청을 처리하지 못했습니다'
}

async function refresh(): Promise<void> {
  try {
    notes.value = await listNotes()
    state.value = 'ready'
    error.value = ''
  } catch (e) {
    state.value = 'error'
    error.value = describe(e)
  }
}

async function add(): Promise<void> {
  if (!title.value.trim() || busy.value) return
  busy.value = true
  try {
    await createNote(title.value.trim(), body.value)
    title.value = ''
    body.value = ''
    await refresh()
  } catch (e) {
    error.value = describe(e)
  } finally {
    busy.value = false
  }
}

async function remove(id: number): Promise<void> {
  try {
    await deleteNote(id)
    await refresh()
  } catch (e) {
    error.value = describe(e)
  }
}

let stopListening = (): void => {}
onMounted(() => {
  stopListening = onBlocked(() => {
    blocked.value = true
  })
  void refresh()
})
onUnmounted(() => stopListening())
</script>

<template>
  <div v-if="blocked" class="blocked">
    <div>
      <h1>접근이 차단되었습니다</h1>
      <p class="muted">비정상적인 사용 환경이 감지되어 세션이 종료되었습니다. 개발자 도구를 닫고 새로고침해 주세요.</p>
    </div>
  </div>

  <main v-else>
    <h1>__PROJECT_NAME__</h1>
    <p class="muted">
      보안 채널:
      <span v-if="state === 'connecting'" class="status">연결 중…</span>
      <span v-else-if="state === 'ready'" class="status ok">{{ channelEnabled ? '서명 + 암호화' : '꺼짐 (개발 모드)' }}</span>
      <span v-else class="status error">오류</span>
    </p>
    <p v-if="error" class="error">{{ error }}</p>

    <section class="panel">
      <form @submit.prevent="add">
        <input v-model="title" maxlength="100" placeholder="제목" aria-label="제목" required />
        <textarea v-model="body" maxlength="4000" placeholder="내용" aria-label="내용"></textarea>
        <button type="submit" :disabled="busy">추가</button>
      </form>
    </section>

    <section class="panel">
      <p v-if="notes.length === 0" class="muted">아직 노트가 없습니다.</p>
      <ul v-else class="notes">
        <li v-for="note in notes" :key="note.id">
          <div>
            <strong>{{ note.title }}</strong>
            <p>{{ note.body }}</p>
          </div>
          <button type="button" class="ghost" @click="remove(note.id)">삭제</button>
        </li>
      </ul>
    </section>
  </main>
</template>
