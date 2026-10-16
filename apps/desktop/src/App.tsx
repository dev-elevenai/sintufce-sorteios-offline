import { useEffect, useState } from 'react'
import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'

type EventState = { id:string; name:string; status:string; eligibleCount:number; prizeCount:number; drawCount:number; listHash:string; prizesHash:string; seedHash?:string|null }
type Draw = { sequence:number; ticket:string; participantName:string; siape:string; prize:string; status:string }
type FormErrors = { contest?: string; numbers: string[] }
const statusName: Record<string, string> = { CONFERIDO: 'Preparando', LACRADO: 'Lacrado', EM_SORTEIO: 'Em andamento', FINALIZADO: 'Finalizado' }

export function App() {
  const [events, setEvents] = useState<EventState[]>([])
  const [event, setEvent] = useState<EventState | null>(null)
  const [contest, setContest] = useState('')
  const [numbers, setNumbers] = useState(['', '', '', '', ''])
  const [review, setReview] = useState(false)
  const [errors, setErrors] = useState<FormErrors>({ numbers: [] })
  const [lastDraw, setLastDraw] = useState<Draw | null>(null)
  const [draws, setDraws] = useState<Draw[]>([])
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => { void invoke<EventState[]>('list_events').then(setEvents).catch(value => setError(String(value))) }, [])

  async function execute(action: () => Promise<unknown>) {
    setBusy(true); setError(''); setSuccess('')
    try { await action() } catch (value) { setError(String(value)) } finally { setBusy(false) }
  }
  async function showEvent(state: EventState) {
    setEvent(state); setDraws([]); setLastDraw(null)
    const history = await invoke<Draw[]>('list_draws')
    setDraws(history); setLastDraw(history.at(-1) ?? null)
    setContest(''); setNumbers(['', '', '', '', '']); setReview(false); setErrors({ numbers: [] })
    setEvents(await invoke<EventState[]>('list_events'))
  }
  async function backToEvents() {
    await execute(async () => { setEvents(await invoke<EventState[]>('list_events')); setEvent(null); setReview(false) })
  }
  async function selectEvent(id: string) {
    await execute(async () => { await showEvent(await invoke<EventState>('select_event', { eventId: id })) })
  }
  async function importPackage() {
    await execute(async () => {
      const path = await open({ multiple: false, filters: [{ name: 'Pacote SINTUFCE', extensions: ['sintufce'] }] })
      if (path && !Array.isArray(path)) await showEvent(await invoke<EventState>('import_package', { path }))
    })
  }
  function validate() {
    const next: FormErrors = { numbers: [] }
    if (!/^\d+$/.test(contest) || !Number.isSafeInteger(Number(contest)) || Number(contest) <= 0) next.contest = 'Informe um concurso inteiro maior que zero, usando apenas números.'
    numbers.forEach((value, index) => {
      if (!/^\d{1,6}$/.test(value)) next.numbers[index] = 'Use de 1 a 6 dígitos, entre 0 e 999999.'
    })
    setErrors(next)
    return !next.contest && !next.numbers.some(Boolean)
  }
  function advance() { if (validate()) { setReview(true); setError('') } }
  async function seal() {
    if (!validate()) { setReview(false); return }
    await execute(async () => {
      setEvent(await invoke<EventState>('seal_event', { input: { contest: Number(contest), numbers: numbers.map(Number) } }))
      setReview(false)
    })
  }
  async function draw() {
    await execute(async () => {
      const result = await invoke<Draw>('draw_next')
      setLastDraw(result); setDraws(await invoke<Draw[]>('list_draws')); setEvent(await invoke<EventState>('get_event_state'))
    })
  }
  async function absent() {
    if (!lastDraw || lastDraw.status !== 'VALID') return
    await execute(async () => {
      await invoke('mark_absent', { sequence: lastDraw.sequence })
      setLastDraw(null); setDraws(await invoke<Draw[]>('list_draws')); setEvent(await invoke<EventState>('get_event_state'))
    })
  }
  async function finish() { await execute(async () => { setEvent(await invoke<EventState>('finish_event')); setLastDraw(null) }) }
  async function exportReport() {
    if (!event) return
    await execute(async () => {
      const path = await save({ defaultPath: `resultado-${event.id}.sintufce-result`, filters: [{ name: 'Resultado SINTUFCE assinado', extensions: ['sintufce-result'] }] })
      if (path) { await invoke('export_report', { path }); setSuccess('Resultado assinado salvo com sucesso.') }
    })
  }
  const federalKey = numbers.map(value => String(Number(value) % 1000).padStart(3, '0')).join('')

  return <main>
    <header><div><span className="eyebrow">SINTUFCE</span><h1>Sorteios Offline</h1><p>Seus eventos ficam salvos neste computador.</p></div><span className="version">v0.2.1</span></header>
    {error && <div className="error" role="alert">{error}</div>}
    {success && <div className="success" role="status">{success}</div>}
    {!event ? <>
      <section className="panel catalog-heading"><div><h2>Meus sorteios</h2><p>Importe um novo evento ou continue um sorteio salvo.</p></div><button disabled={busy} onClick={() => void importPackage()}>Importar pacote .sintufce</button></section>
      {events.length === 0 && <section className="panel hero"><h2>Nenhum evento importado</h2><p>Selecione o pacote assinado gerado pelo sistema web para começar.</p></section>}
      <div className="event-grid">{events.map(item => <article className="panel event-card" key={item.id}><span className={`badge ${item.status === 'FINALIZADO' ? 'finished' : ''}`}>{statusName[item.status] ?? item.status}</span><h2>{item.name}</h2><p>{item.eligibleCount} elegíveis · {item.prizeCount} prêmios · {item.drawCount} contemplados</p><button disabled={busy} onClick={() => void selectEvent(item.id)}>{item.status === 'FINALIZADO' ? 'Ver histórico' : 'Abrir / continuar'}</button></article>)}</div>
    </> : <>
      <button className="back" disabled={busy} onClick={() => void backToEvents()}>← Voltar para meus sorteios</button>
      <section className="status"><strong>{event.name}</strong><span className="badge">{statusName[event.status] ?? event.status}</span></section>
      <section className="metrics"><div><b>{event.eligibleCount}</b><span>Elegíveis</span></div><div><b>{event.prizeCount}</b><span>Prêmios</span></div><div><b>{event.drawCount}</b><span>Contemplados</span></div></section>
      {event.status === 'CONFERIDO' && <section className="panel">
        <div className="steps"><span className={!review ? 'current' : ''}>1. Informar números</span><span className={review ? 'current' : ''}>2. Conferir e lacrar</span></div>
        {!review ? <><h2>Loteria Federal</h2><p>Informe os cinco números na ordem oficial. Você poderá conferir tudo antes de lacrar.</p>
          <label htmlFor="contest">Número do concurso<input id="contest" value={contest} onChange={e => setContest(e.target.value)} inputMode="numeric" pattern="[0-9]*" maxLength={16} aria-invalid={!!errors.contest} aria-describedby={errors.contest ? 'contest-error' : undefined} disabled={busy} /></label>
          {errors.contest && <p className="field-error" id="contest-error">{errors.contest}</p>}
          <div className="numbers">{numbers.map((value, index) => <div key={index}><label htmlFor={`number-${index}`}>{index + 1}º prêmio<input id={`number-${index}`} value={value} onChange={e => setNumbers(current => current.map((item, i) => i === index ? e.target.value : item))} inputMode="numeric" pattern="[0-9]*" maxLength={6} aria-invalid={!!errors.numbers[index]} aria-describedby={errors.numbers[index] ? `number-error-${index}` : undefined} disabled={busy} /></label>{errors.numbers[index] && <p className="field-error" id={`number-error-${index}`}>{errors.numbers[index]}</p>}</div>)}</div>
          <button disabled={busy} onClick={advance}>Revisar números →</button>
        </> : <><h2>Confira antes de lacrar</h2><p>Depois do lacre, os números ficam registrados e não podem ser alterados.</p><dl className="review"><dt>Concurso</dt><dd>{contest}</dd><dt>Números na ordem oficial</dt><dd>{numbers.join(' · ')}</dd><dt>Chave do sorteio</dt><dd className="key">{federalKey}</dd></dl><div className="actions"><button className="secondary" disabled={busy} onClick={() => setReview(false)}>← Voltar e corrigir</button><button disabled={busy} onClick={() => void seal()}>{busy ? 'Lacrando...' : 'Confirmar e lacrar'}</button></div></>}
      </section>}
      {(event.status === 'LACRADO' || event.status === 'EM_SORTEIO') && <section className="panel draw-area"><h2>Área de sorteio</h2><p>O progresso é salvo a cada chamada. Você pode fechar e continuar depois.</p>{lastDraw && <article className="winner"><span>{lastDraw.sequence}ª chamada · {lastDraw.prize}</span><strong>{lastDraw.participantName}</strong><small>SIAPE {lastDraw.siape} · Ticket {lastDraw.ticket}</small>{lastDraw.status === 'VALID' && <button className="secondary" disabled={busy} onClick={() => void absent()}>Registrar ausência</button>}</article>}<button onClick={() => void draw()} disabled={busy || event.drawCount >= event.prizeCount}>{busy ? 'Confirmando...' : 'Realizar próxima chamada'}</button>{event.drawCount >= event.prizeCount && <button className="secondary" disabled={busy} onClick={() => void finish()}>Finalizar evento</button>}</section>}
      {draws.length > 0 && <section className="panel"><h2>Histórico de chamadas</h2><div className="table-wrap"><table><thead><tr><th>#</th><th>Prêmio</th><th>Participante</th><th>Ticket</th><th>Situação</th></tr></thead><tbody>{draws.map(item => <tr key={item.sequence}><td>{item.sequence}</td><td>{item.prize}</td><td>{item.participantName}</td><td>{item.ticket}</td><td>{item.status === 'VALID' ? 'Válida' : 'Ausente'}</td></tr>)}</tbody></table></div></section>}
      {event.status === 'FINALIZADO' && <section className="panel"><h2>Evento finalizado</h2><p>Este histórico está preservado. Para outro sorteio, volte aos eventos e importe um novo pacote.</p><button disabled={busy} onClick={() => void exportReport()}>Exportar resultado assinado</button></section>}
      <details><summary>Integridade do evento</summary><code>Lista: {event.listHash}</code><code>Prêmios: {event.prizesHash}</code>{event.seedHash && <code>Semente: {event.seedHash}</code>}</details>
    </>}
  </main>
}
