const etapas = ['Importar pacote', 'Conferir listas', 'Lacrar evento', 'Realizar sorteio', 'Finalizar e exportar']
export function App() {
  return <main><header><span className="eyebrow">SINTUFCE</span><h1>Sorteios Offline</h1><p>Operação local, sem conexão de rede.</p></header><section className="status" aria-label="Estado da instalação"><strong>Ambiente isolado</strong><span>Nenhum evento carregado</span></section><ol>{etapas.map((etapa, index) => <li key={etapa}><span>{index + 1}</span>{etapa}</li>)}</ol><button type="button" disabled>Selecionar pacote .sintufce</button><small>Fundação técnica — importação será habilitada após homologação do formato.</small></main>
}
