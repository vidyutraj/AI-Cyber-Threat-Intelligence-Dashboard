import { useEffect, useRef, useState, useCallback } from 'react'
import * as d3 from 'd3'
import './IOCGraph.css'

import { API_BASE } from '../config.js'

const TYPE_COLORS = {
  cve:       '#e3b341',
  ip:        '#7ee787',
  domain:    '#79c0ff',
  hash:      '#d2a8ff',
  malware:   '#ff7b72',
  technique: '#8b949e',
}

const TYPE_RADIUS = {
  cve:       8,
  ip:        7,
  domain:    7,
  hash:      5,
  malware:   9,
  technique: 6,
}

function nodeRadius(d) {
  const base = TYPE_RADIUS[d.type] || 6
  return base + Math.min(d.degree * 0.4, 8)
}

export default function IOCGraph({ hours = 168 }) {
  const svgRef = useRef(null)
  const [graphData, setGraphData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [tooltip, setTooltip] = useState(null)
  const [selected, setSelected] = useState(null)
  const [filterType, setFilterType] = useState('all')
  const [topN, setTopN] = useState(60)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch(
        `${API_BASE}/api/intel/graph?hours=${hours}&top_n=${topN}`,
      )
      const json = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(json.error || 'Graph load failed')
      setGraphData(json)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [hours, topN])

  useEffect(() => { load() }, [load])

  // D3 simulation
  useEffect(() => {
    if (!graphData || !svgRef.current) return

    const container = svgRef.current.parentElement
    const W = container.clientWidth || 700
    const H = Math.min(W * 0.7, 520)

    // Filter by type if requested
    const activeTypes = filterType === 'all'
      ? null
      : new Set(filterType.split(','))

    const nodeSet = activeTypes
      ? new Set(graphData.nodes.filter(n => activeTypes.has(n.type)).map(n => n.id))
      : null

    const nodes = (graphData.nodes || [])
      .filter(n => !nodeSet || nodeSet.has(n.id))
      .map(n => ({ ...n }))

    const nodeIds = new Set(nodes.map(n => n.id))
    const edges = (graphData.edges || [])
      .filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
      .map(e => ({ ...e }))

    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()
    svg.attr('width', W).attr('height', H)

    const g = svg.append('g')

    // Zoom + pan
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (ev) => g.attr('transform', ev.transform))
    svg.call(zoom)

    // Edge weight → stroke opacity/width
    const maxW = d3.max(edges, e => e.weight) || 1

    const link = g.append('g')
      .selectAll('line')
      .data(edges)
      .join('line')
      .attr('stroke', '#30363d')
      .attr('stroke-opacity', d => 0.15 + (d.weight / maxW) * 0.55)
      .attr('stroke-width', d => 0.5 + (d.weight / maxW) * 2.5)

    // Node circles
    const node = g.append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', nodeRadius)
      .attr('fill', d => TYPE_COLORS[d.type] || '#8b949e')
      .attr('fill-opacity', 0.85)
      .attr('stroke', d => selected?.id === d.id ? '#fff' : 'transparent')
      .attr('stroke-width', 2)
      .attr('cursor', 'pointer')
      .on('mouseover', (ev, d) => {
        setTooltip({
          x: ev.clientX,
          y: ev.clientY,
          node: d,
        })
      })
      .on('mousemove', (ev) => {
        setTooltip(t => t ? { ...t, x: ev.clientX, y: ev.clientY } : null)
      })
      .on('mouseout', () => setTooltip(null))
      .on('click', (ev, d) => {
        ev.stopPropagation()
        setSelected(sel => sel?.id === d.id ? null : d)
      })
      .call(
        d3.drag()
          .on('start', (ev, d) => {
            if (!ev.active) sim.alphaTarget(0.3).restart()
            d.fx = d.x; d.fy = d.y
          })
          .on('drag', (ev, d) => { d.fx = ev.x; d.fy = ev.y })
          .on('end', (ev, d) => {
            if (!ev.active) sim.alphaTarget(0)
            d.fx = null; d.fy = null
          }),
      )

    // Labels for high-degree nodes
    const labelThreshold = d3.quantile(nodes.map(n => n.degree).sort(d3.ascending), 0.75) || 3
    g.append('g')
      .selectAll('text')
      .data(nodes.filter(n => n.degree >= labelThreshold))
      .join('text')
      .text(d => d.value.length > 18 ? d.value.slice(0, 16) + '…' : d.value)
      .attr('font-size', '9px')
      .attr('fill', '#94a3b8')
      .attr('text-anchor', 'middle')
      .attr('dy', d => -nodeRadius(d) - 3)
      .attr('pointer-events', 'none')

    // Force simulation
    const sim = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges)
        .id(d => d.id)
        .distance(d => 40 + 60 / (d.weight || 1))
        .strength(0.3))
      .force('charge', d3.forceManyBody()
        .strength(d => -40 - nodeRadius(d) * 4))
      .force('center', d3.forceCenter(W / 2, H / 2))
      .force('collision', d3.forceCollide().radius(d => nodeRadius(d) + 3))
      .on('tick', () => {
        link
          .attr('x1', d => d.source.x)
          .attr('y1', d => d.source.y)
          .attr('x2', d => d.target.x)
          .attr('y2', d => d.target.y)
        node
          .attr('cx', d => d.x)
          .attr('cy', d => d.y)
        g.selectAll('text')
          .attr('x', d => d.x)
          .attr('y', d => d.y)
      })

    svg.on('click', () => setSelected(null))

    return () => sim.stop()
  }, [graphData, filterType, selected?.id])

  const types = graphData
    ? [...new Set(graphData.nodes.map(n => n.type))].sort()
    : []

  return (
    <div className="iocgraph">
      <div className="iocgraph-toolbar">
        <div className="iocgraph-filters">
          <button
            className={`iocgraph-type-btn ${filterType === 'all' ? 'active' : ''}`}
            onClick={() => setFilterType('all')}
          >All</button>
          {types.map(t => (
            <button
              key={t}
              className={`iocgraph-type-btn iocgraph-type-btn--${t} ${filterType === t ? 'active' : ''}`}
              onClick={() => setFilterType(f => f === t ? 'all' : t)}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="iocgraph-controls">
          <label className="iocgraph-label">
            Nodes
            <select
              className="iocgraph-select"
              value={topN}
              onChange={e => setTopN(Number(e.target.value))}
            >
              {[30, 60, 100, 150].map(n => (
                <option key={n} value={n}>{n}</option>
              ))}
            </select>
          </label>
          <button className="iocgraph-reload-btn" onClick={load} disabled={loading}>
            {loading ? 'Loading…' : 'Reload'}
          </button>
        </div>
      </div>

      {error && <div className="iocgraph-error">{error}</div>}

      <div className="iocgraph-canvas-wrap">
        <svg ref={svgRef} className="iocgraph-svg" />
        {loading && (
          <div className="iocgraph-overlay">
            Building correlation graph…
          </div>
        )}
      </div>

      {graphData && (
        <div className="iocgraph-footer">
          <span>{graphData.nodes?.length || 0} nodes</span>
          <span>{graphData.edges?.length || 0} edges</span>
          <span>{graphData.n_articles} articles</span>
          <span className="iocgraph-hint">Drag nodes · Scroll to zoom · Click to inspect</span>
        </div>
      )}

      {/* Legend */}
      <div className="iocgraph-legend">
        {Object.entries(TYPE_COLORS).map(([t, c]) => (
          <span key={t} className="iocgraph-legend-item">
            <span className="iocgraph-legend-dot" style={{ background: c }} />
            {t}
          </span>
        ))}
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="iocgraph-tooltip"
          style={{ left: tooltip.x + 14, top: tooltip.y - 14 }}
        >
          <div className="iocgraph-tt-type">{tooltip.node.type}</div>
          <div className="iocgraph-tt-value">{tooltip.node.value}</div>
          <div className="iocgraph-tt-stats">
            degree {tooltip.node.degree} · eig {tooltip.node.eigenvector?.toFixed(3)} · c{tooltip.node.community}
          </div>
        </div>
      )}

      {/* Side panel for selected node */}
      {selected && (
        <div className="iocgraph-sidepanel">
          <div className="iocgraph-sp-head">
            <span className={`ti-type-tag ti-type-tag--${selected.type}`}>{selected.type}</span>
            <span className="iocgraph-sp-value">{selected.value}</span>
            <button className="iocgraph-sp-close" onClick={() => setSelected(null)}>✕</button>
          </div>
          <div className="iocgraph-sp-metrics">
            <div><label>Degree</label> <span>{selected.degree}</span></div>
            <div><label>Eigenvector</label> <span>{selected.eigenvector?.toFixed(4)}</span></div>
            <div><label>Mentions</label> <span>{selected.count}</span></div>
            <div><label>Community</label> <span>{selected.community}</span></div>
          </div>
          {selected.sample_articles?.length > 0 && (
            <div className="iocgraph-sp-articles">
              <h4>Articles mentioning this IOC</h4>
              {selected.sample_articles.map((a, i) => (
                <a key={i} href={a.url || '#'} target="_blank" rel="noreferrer"
                  className="iocgraph-sp-article-link">
                  <span className="iocgraph-sp-article-src">{a.source_label}</span>
                  {a.title}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
