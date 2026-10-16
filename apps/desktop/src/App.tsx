import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'

type EventState = { id:string; name:string; status:string; eligibleCount:number; prizeCount:number; drawCount:number; listHash:string; prizesHash:string; seedHash?:string|null }
type Draw = { sequence:number; ticket:string; participantName:string; siape:string; prize:string }

export function App() {
  const [event, setEvent] = useState<EventState | null>(null)
  const [contest, setContest] = useState('')
  const [numbers, setNumbers] = useState(['', '', '', '', ''])
  const [secrets, setSecrets] = useState(['', '', ''])
  const [lastDraw, setLastDraw] = useState<Draw | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { void invoke<EventState | null>('get_event_state').then(setEvent).catch(() => undefined) }, [])

  async function execute(action: () => Promise<unknown>) { setBusy(true); setError(''); try { await action() } catch (value) { setError(String(value)) } finally { setBusy(false) } }
  async function importPackage() {
    const path = await open({ multiple: false, filters: [{ name: 'Pacote SINTUFCE', extensions: ['sintufce'] }] })
    if (path && !Array.isArray(path)) await execute(() => invoke<EventState>('import_package', { path }).then(setEvent))
  }
  async function seal() { await execute(() => invoke<EventState>('seal_event', { input: { contest: Number(contest), numbers: numbers.map(Number), auditorSecrets: secrets } }).then(setEvent)) }
  async function draw() { await execute(async () => { setLastDraw(await invoke<Draw>('draw_next')); setEvent(await invoke<EventState>('get_event_state')) }) }
  async function absent() { if (!lastDraw) return; await execute(async () => { await invoke('mark_absent', { sequence: lastDraw.sequence }); setLastDraw(null); setEvent(await invoke<EventState>('get_event_state')) }) }
  async function finish() { await execute(() => invoke<EventState>('finish_event').then(setEvent)) }
  async function exportReport() { const path = await save({ defaultPath: `ata-${event?.name ?? 'sorteio'}.json`, filters: [{ name: 'Relatório verificável', extensions: ['json'] }] }); if (path) await execute(() => invoke('export_report', { path })) }

  return <main>
    <header><span className="eyebrow">SINTUFCE</span><h1>Sorteios Offline</h1><p>Operação local, sem conexão de rede.</p></header>
    {error && <div className="error" role="alert">{error}</div>}
    {!event && <section className="panel hero"><h2>Importar pacote lacrado</h2><p>Conecte a mídia com o arquivo gerado pelo sistema SINTUFCE.</p><button onClick={() => void importPackage()} disabled={busy}>Selecionar pacote .sintufce</button></section>}
    {event && <><section className="status"><strong>{event.name}</strong><span>{event.status}</span></section><section className="metrics"><div><b>{event.eligibleCount}</b><span>Elegíveis</span></div><div><b>{event.prizeCount}</b><span>Prêmios</span></div><div><b>{event.drawCount}</b><span>Chamadas</span></div></section><details><summary>Compromissos de integridade</summary><code>Lista: {event.listHash}</code><code>Prêmios: {event.prizesHash}</code>{event.seedHash && <code>Semente: {event.seedHash}</code>}</details></>}
    {event?.status === 'CONFERIDO' && <section className="panel"><h2>Lacrar evento</h2><p>Informe o concurso, os cinco resultados e três segredos independentes produzidos pelos auditores.</p><label>Concurso da Federal<input value={contest} onChange={e => setContest(e.target.value)} inputMode="numeric" /></label><div className="numbers">{numbers.map((value, index) => <input key={index} value={value} onChange={e => setNumbers(current => current.map((item, i) => i === index ? e.target.value : item))} placeholder={`${index + 1}º`} inputMode="numeric" />)}</div>{secrets.map((value, index) => <label key={index}>Segredo hexadecimal do auditor {index + 1}<input value={value} onChange={e => setSecrets(current => current.map((item, i) => i === index ? e.target.value : item))} placeholder="64 caracteres" autoComplete="off" /></label>)}<button onClick={() => void seal()} disabled={busy || !contest || numbers.some(value => !value) || secrets.some(value => value.length !== 64)}>Conferir e lacrar definitivamente</button></section>}
    {(event?.status === 'LACRADO' || event?.status === 'EM_SORTEIO') && <section className="panel draw-area"><h2>Área de sorteio</h2>{lastDraw && <article className="winner"><span>{lastDraw.sequence}ª chamada · {lastDraw.prize}</span><strong>{lastDraw.participantName}</strong><small>SIAPE {lastDraw.siape} · Ticket {lastDraw.ticket}</small><button className="secondary" onClick={() => void absent()}>Registrar ausência</button></article>}<button onClick={() => void draw()} disabled={busy || event.drawCount >= event.prizeCount}>{busy ? 'Confirmando...' : 'Realizar próxima chamada'}</button>{event.drawCount >= event.prizeCount && <button className="secondary" onClick={() => void finish()}>Finalizar evento</button>}</section>}
    {event?.status === 'FINALIZADO' && <section className="panel"><h2>Evento finalizado</h2><p>O histórico está bloqueado para alterações.</p><button onClick={() => void exportReport()}>Exportar relatório verificável</button></section>}
  </main>
}
